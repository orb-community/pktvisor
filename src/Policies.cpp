/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Policies.h"
#include "CoreRegistry.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "Taps.h"
#include <algorithm>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

namespace visor {

std::vector<Policy *> PolicyManager::load_from_str(const std::string &str)
{
    if (str.empty()) {
        throw PolicyException("empty data");
    }

    YAML::Node node = YAML::Load(str);

    if (!node.IsMap() || !node["visor"]) {
        throw PolicyException("invalid schema");
    }
    if (!node["version"] || !node["version"].IsScalar() || node["version"].as<std::string>() != "1.0") {
        throw PolicyException("missing or unsupported version");
    }
    if (node["visor"]["policies"] && node["visor"]["policies"].IsMap()) {
        return load(node["visor"]["policies"]);
    } else {
        throw PolicyException("no policies found in schema");
    }
}

// needs to be thread safe and transactional: any errors mean resources get cleaned up with no side effects
std::vector<Policy *> PolicyManager::load(const YAML::Node &policy_yaml)
{
    assert(policy_yaml.IsMap());
    assert(spdlog::get("visor"));

    std::vector<Policy *> result;
    for (YAML::const_iterator it = policy_yaml.begin(); it != policy_yaml.end(); ++it) {

        // serialized policy loads
        std::unique_lock lock(_load_mutex);

        // Basic Structure
        if (!it->first.IsScalar()) {
            throw PolicyException("expecting policy identifier");
        }
        auto policy_name = it->first.as<std::string>();
        spdlog::get("visor")->info("policy [{}]: parsing", policy_name);
        if (!it->second.IsMap()) {
            throw PolicyException("expecting policy configuration map");
        }
        // Ensure policy name isn't already defined
        if (module_exists(policy_name)) {
            throw PolicyException(fmt::format("policy with name '{}' already defined", policy_name));
        }

        // Policy kind defines schema
        if (!it->second["kind"] || !it->second["kind"].IsScalar()) {
            throw PolicyException("missing or invalid policy kind at key 'kind'");
        }
        if (it->second["kind"].as<std::string>() != "collection") {
            throw PolicyException(fmt::format("unknown policy kind: {}", it->second["kind"].as<std::string>()));
        }

        // Input Section
        if (!it->second["input"] || !it->second["input"].IsMap()) {
            throw PolicyException("missing or invalid policy input stream configuration at key 'input'");
        }
        auto input_node = it->second["input"];
        if (!input_node["tap"] || !input_node["tap"].IsScalar()) {
            throw PolicyException("missing or invalid tap at key 'input.tap'");
        }
        if (!input_node["input_type"] || !input_node["input_type"].IsScalar()) {
            throw PolicyException("missing or invalid input_type at key 'input.input_type'");
        }

        // Tap
        Tap *tap{nullptr};
        std::unique_lock<std::shared_mutex> tap_lock;
        auto tap_name = input_node["tap"].as<std::string>();
        if (!_registry->tap_manager()->module_exists(tap_name)) {
            throw PolicyException(fmt::format("tap '{}' does not exist", tap_name));
        }
        try {
            auto result = _registry->tap_manager()->module_get_locked(tap_name);
            tap = result.module;
            tap_lock = std::move(result.lock);
        } catch (ModuleException &e) {
            throw PolicyException(fmt::format("unable to retrieve tap '{}': {}", tap_name, e.what()));
        }

        // Tap Input Config and Filter
        Config tap_filter;
        if (input_node["filter"]) {
            if (!input_node["filter"].IsMap()) {
                throw PolicyException("input filter configuration is not a map");
            }
            try {
                tap_filter.config_set_yaml(input_node["filter"]);
            } catch (ConfigException &e) {
                throw PolicyException(fmt::format("invalid input filter for tap '{}': {}", tap_name, e.what()));
            }
        }
        Config tap_config;
        if (input_node["config"]) {
            if (!input_node["config"].IsMap()) {
                throw PolicyException("input configuration is not a map");
            }
            try {
                tap_config.config_set_yaml(input_node["config"]);
            } catch (ConfigException &e) {
                throw PolicyException(fmt::format("invalid input config for tap '{}': {}", tap_name, e.what()));
            }
        }

        std::string input_stream_module_name = tap_config.config_hash();
        input_stream_module_name.insert(0, tap->name() + "-");

        std::unique_ptr<InputStream> input_stream;
        InputStream *input_ptr;
        std::unique_lock<std::shared_mutex> input_lock;
        if (_registry->input_manager()->module_exists(input_stream_module_name)) {
            spdlog::get("visor")->info("policy [{}]: input stream already exists. reusing: {}", policy_name, input_stream_module_name);
            auto result_input = _registry->input_manager()->module_get_locked(input_stream_module_name);
            input_ptr = result_input.module;
            input_lock = std::move(result_input.lock);
        } else {
            // Instantiate stream from tap
            try {
                spdlog::get("visor")->info("policy [{}]: instantiating Tap: {}", policy_name, tap_name);
                input_stream = tap->instantiate(&tap_config, &tap_filter, input_stream_module_name);
                // ensure tap input type matches policy input tap
                if (input_node["input_type"].as<std::string>() != tap->input_plugin()->plugin()) {
                    throw PolicyException(fmt::format("input_type for policy specified tap '{}' doesn't match tap's defined input type: {}/{}", tap_name, input_node["input_type"].as<std::string>(), tap->input_plugin()->plugin()));
                }
                input_ptr = input_stream.get();
            } catch (std::runtime_error &e) {
                throw PolicyException(fmt::format("unable to instantiate tap '{}': {}", tap_name, e.what()));
            }
        }

        auto input_event_proxy = input_ptr->add_event_proxy(tap_filter);

        // Handler type
        if (!it->second["handlers"] || !it->second["handlers"].IsMap()) {
            throw PolicyException("missing or invalid handler configuration at key 'handlers'");
        }
        auto handler_node = it->second["handlers"];
        bool handler_sequence = false;
        if (!handler_node["modules"] || (!handler_node["modules"].IsMap() && !handler_node["modules"].IsSequence())) {
            throw PolicyException("missing or invalid handler modules at key 'modules'");
        } else if (handler_node["modules"].IsSequence()) {
            handler_sequence = true;
        }

        // Create Policy
        auto policy = std::make_unique<Policy>(policy_name, tap, handler_sequence);
        // if and only if policy succeeds, we will return this in result set
        Policy *policy_ptr = policy.get();
        policy->set_input_stream(input_ptr);

        // Handler Section
        Config window_config;
        if (handler_node["window_config"] && handler_node["window_config"].IsMap()) {
            try {
                window_config.config_set_yaml(handler_node["window_config"]);
            } catch (ConfigException &e) {
                throw PolicyException(fmt::format("invalid stream handler window config: {}", e.what()));
            }
        } else {
            window_config.config_set<uint64_t>("num_periods", _default_num_periods);
            window_config.config_set<uint64_t>("deep_sample_rate", _default_deep_sample_rate);
        }

        std::unique_ptr<Policy> input_resources_policy;
        Policy *input_res_policy_ptr{nullptr};
        std::unique_ptr<StreamHandler> resources_module;
        if (input_stream) {
            // create new policy with resources handler for input stream
            input_resources_policy = std::make_unique<Policy>(input_stream_module_name + "-resources", tap, false);
            input_resources_policy->set_input_stream(input_ptr);
            auto resources_handler_plugin = _registry->handler_plugins().find("input_resources");
            if (resources_handler_plugin != _registry->handler_plugins().end()) {
                resources_module = resources_handler_plugin->second->instantiate(input_stream_module_name + "-resources", input_event_proxy, &window_config, nullptr);
                input_resources_policy->add_module(resources_module.get());
                input_res_policy_ptr = input_resources_policy.get();
            }
        }

        std::vector<std::unique_ptr<StreamHandler>> handler_modules;
        for (YAML::const_iterator h_it = handler_node["modules"].begin(); h_it != handler_node["modules"].end(); ++h_it) {

            // Per handler
            auto module = [&]() -> const YAML::Node {
                return handler_sequence ? *h_it : h_it->second;
            }();

            std::string handler_module_name;
            if (handler_sequence) {
                if (!module.begin()->first.IsScalar()) {
                    throw PolicyException("expecting handler module identifier");
                }
                handler_module_name = module.begin()->first.as<std::string>();
            } else {
                if (!h_it->first.IsScalar()) {
                    throw PolicyException("expecting handler module identifier");
                }
                handler_module_name = h_it->first.as<std::string>();
            }

            if (!module.IsMap()) {
                throw PolicyException("expecting Handler configuration map");
            }

            if (!module["type"] || !module["type"].IsScalar()) {
                module = module[handler_module_name];
                if (!module["type"] || !module["type"].IsScalar()) {
                    throw PolicyException("missing or invalid stream handler type at key 'type'");
                }
            }
            auto handler_module_type = module["type"].as<std::string>();
            auto handler_plugin = _registry->handler_plugins().find(handler_module_type);
            if (handler_plugin == _registry->handler_plugins().end()) {
                throw PolicyException(fmt::format("Policy '{}' requires stream handler type '{}' which is not available", policy_name, handler_module_type));
            }
            Config handler_filter;
            if (module["filter"]) {
                if (!module["filter"].IsMap()) {
                    throw PolicyException("stream handler filter configuration is not a map");
                }
                try {
                    handler_filter.config_set_yaml(module["filter"]);
                } catch (ConfigException &e) {
                    throw PolicyException(fmt::format("invalid stream handler filter config for handler '{}': {}", handler_module_name, e.what()));
                }
            }
            Config handler_config;
            if (module["config"]) {
                if (!module["config"].IsMap()) {
                    throw PolicyException("stream handler configuration is not a map");
                }
                try {
                    handler_config.config_set_yaml(module["config"]);
                } catch (ConfigException &e) {
                    throw PolicyException(fmt::format("invalid stream handler config for handler '{}': {}", handler_module_name, e.what()));
                }
            }
            Config handler_metrics;
            if (module["metric_groups"]) {
                if (!module["metric_groups"].IsMap()) {
                    throw PolicyException("stream handler metric groups is not a map");
                }

                if (!module["metric_groups"]["enable"] && !module["metric_groups"]["disable"]) {
                    throw PolicyException("stream handler metric groups should contain enable and/or disable tags");
                }

                try {
                    handler_config.config_set_yaml(module["metric_groups"]);
                } catch (ConfigException &e) {
                    throw PolicyException(fmt::format("invalid stream handler metrics for handler '{}': {}", handler_module_name, e.what()));
                }
            }
            spdlog::get("visor")->info("policy [{}]: instantiating Handler {} of type {}", policy_name, handler_module_name, handler_module_type);
            // note, currently merging the handler config with the window config. do they need to be separate?
            handler_config.config_merge(window_config);
            handler_filter.config_merge(handler_metrics);

            std::unique_ptr<StreamHandler> handler_module;
            if (!handler_sequence || handler_modules.empty()) {
                handler_module = handler_plugin->second->instantiate(policy_name + "-" + handler_module_name, input_event_proxy, &handler_config, &handler_filter);
            } else {
                // for sequence, use only previous handler
                handler_module = handler_plugin->second->instantiate(policy_name + "-" + handler_module_name, nullptr, &handler_config, &handler_filter, handler_modules.back().get());
            }
            policy_ptr->add_module(handler_module.get());
            handler_modules.emplace_back(std::move(handler_module));
        }

        // make sure policy starts before committing
        try {
            policy->start();
            if (input_resources_policy) {
                input_resources_policy->start();
            }
        } catch (std::runtime_error &e) {
            throw PolicyException(fmt::format("policy [{}] failed to start: {}", policy_name, e.what()));
        }

        // Make modules visible in registry
        // If the modules created above go out of scope before this step, they will destruct so the key is to make sure
        // roll back during exception ensures no modules have been added to any of the managers
        try {
            module_add(std::move(policy));
            if (input_resources_policy) {
                module_add(std::move(input_resources_policy));
            }
        } catch (ModuleException &e) {
            throw PolicyException(fmt::format("policy [{}] creation failed (policy): {}", policy_name, e.what()));
        }
        try {
            if (input_stream) {
                _registry->input_manager()->module_add(std::move(input_stream));
            }
        } catch (ModuleException &e) {
            // note that if this call excepts, we are in an unknown state and the exception will propagate
            module_remove(policy_name);
            if (input_res_policy_ptr) {
                module_remove(input_res_policy_ptr->name());
            }
            throw PolicyException(fmt::format("policy [{}] creation failed (input): {}", policy_name, e.what()));
        }
        std::vector<std::string> added_handlers;
        try {
            for (auto &m : handler_modules) {
                auto hname = m->name();
                _registry->handler_manager()->module_add(std::move(m));
                // if it did not except, add it to the list for rollback upon exception
                added_handlers.push_back(hname);
            }
            if (resources_module) {
                auto hname = resources_module->name();
                _registry->handler_manager()->module_add(std::move(resources_module));
                added_handlers.push_back(hname);
            }
        } catch (ModuleException &e) {
            // note that if any of these calls except, we are in an unknown state and the exception will propagate
            // nothing needs to be stopped because it was not started
            module_remove(policy_name);
            if (input_res_policy_ptr) {
                module_remove(input_res_policy_ptr->name());
            }
            _registry->input_manager()->module_remove(input_stream_module_name);
            for (auto &m : added_handlers) {
                _registry->handler_manager()->module_remove(m);
            }
            // at this point no outside reference is held to the modules so they will destruct
            throw PolicyException(fmt::format("policy [{}] creation failed (handler: {}): {}", e.name(), policy_name, e.what()));
        }

        // success
        if (input_res_policy_ptr) {
            input_ptr->add_policy(input_res_policy_ptr);
        }
        input_ptr->add_policy(policy_ptr);
        result.push_back(policy_ptr);
    }
    return result;
}

void PolicyManager::remove_policy(const std::string &name)
{
    std::unique_lock lock(_map_mutex);
    if (_map.count(name) == 0) {
        throw ModuleException(name, fmt::format("module name '{}' does not exist", name));
    }

    auto policy = _map[name].get();
    auto input_stream = policy->input_stream();
    auto input_name = policy->input_stream()->name();
    std::vector<std::string> module_names;
    for (const auto &mod : policy->modules()) {
        module_names.push_back(mod->name());
    }
    policy->stop();

    for (const auto &name : module_names) {
        _registry->handler_manager()->module_remove(name);
    }

    if (input_stream->policies_count() == 1) {
        // if there is only one policy left on the input stream, and that policy is the input resources policy, then remove it
        auto input_resources_name = input_name + "-resources";
        if (name != input_resources_name && _map.count(input_resources_name) != 0) {
            auto resources_policy = _map[input_resources_name].get();
            resources_policy->stop();
            _registry->handler_manager()->module_remove(input_resources_name);
            _map.erase(input_resources_name);
        }
    }

    if (!input_stream->policies_count()) {
        _registry->input_manager()->module_remove(input_name);
    }

    _map.erase(name);
}
void Policy::info_json(json &j) const
{
    _input_stream->info_json(j["input"][_input_stream->name()]);
    for (auto &mod : _modules) {
        mod->info_json(j["modules"][mod->name()]);
    }
}
void Policy::start()
{
    if (_running) {
        return;
    }
    assert(_tap);
    assert(_input_stream);
    spdlog::get("visor")->info("policy [{}]: starting", _name);
    for (auto &mod : _modules) {
        spdlog::get("visor")->info("policy [{}]: starting handler instance: {}", _name, mod->name());
        mod->start();
    }
    // start input stream _after_ modules, since input stream will create a new thread and we need to catch any startup errors
    // from handlers in the same thread we are starting the policy from
    spdlog::get("visor")->info("policy [{}]: starting input instance: {}", _name, _input_stream->name());
    _input_stream->start();
    _running = true;
}
void Policy::stop()
{
    if (!_running) {
        return;
    }
    spdlog::get("visor")->info("policy [{}]: stopping", _name);
    if (_input_stream->running()) {
        if (_input_stream->policies_count() <= 1) {
            spdlog::get("visor")->info("policy [{}]: stopping input instance: {}", _name, _input_stream->name());
            _input_stream->stop();
        } else {
            spdlog::get("visor")->info("policy [{}]: input instance {} not stopped because it is in use by another policy.", _name, _input_stream->name());
        }
    }
    _input_stream->remove_policy(this);
    for (auto &mod : _modules) {
        if (mod->running()) {
            spdlog::get("visor")->info("policy [{}]: stopping handler instance: {}", _name, mod->name());
            mod->stop();
        }
    }
    _running = false;
}

}
