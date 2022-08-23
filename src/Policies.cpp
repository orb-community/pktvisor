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

void PolicyManager::set_default_handler_config(const YAML::Node &config_yaml)
{
    for (YAML::const_iterator it = config_yaml.begin(); it != config_yaml.end(); ++it) {

        auto handler_module_type = it->first.as<std::string>();
        if (!it->second.IsMap()) {
            throw ConfigException("expecting global_handler_config configuration map");
        }

        auto handler_plugin = _registry->handler_plugins().find(handler_module_type);
        if (handler_plugin == _registry->handler_plugins().end()) {
            throw ConfigException(fmt::format("global_handler_config requires stream handler type '{}' which is not available", handler_module_type));
        }

        if (_global_handler_config.count(handler_module_type) > 0) {
            throw ConfigException(fmt::format("stream handler type '{}' already exists in global_handler_config configuration", handler_module_type));
        }

        auto pair = _global_handler_config.emplace(handler_module_type, std::make_unique<Configurable>());
        pair.first->second->config_set_yaml(it->second);
    }
}

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
        if (!input_node["input_type"] || !input_node["input_type"].IsScalar()) {
            throw PolicyException("missing or invalid input_type at key 'input.input_type'");
        }

        if (input_node["tap"] && input_node["tap_selector"]) {
            throw PolicyException("input can have only key 'input.tap' or key 'input.tap_selector'");
        } else if (!input_node["tap"] && !input_node["tap_selector"]) {
            throw PolicyException("missing key 'input.tap' or key 'input.tap_selector'");
        }

        // Create Policy
        auto policy = std::make_unique<Policy>(policy_name);
        if (input_node["tap"]) {
            if (!input_node["tap"].IsScalar()) {
                throw PolicyException("invalid tap at key 'input.tap'");
            }
            auto policy_ptr = policy.get();
            module_add(std::move(policy));
            try {
                _validate_policy(it->second, policy_name, policy_ptr);
            } catch (PolicyException &e) {
                module_remove(policy_name);
                throw;
            }
            result.push_back(policy_ptr);
        } else if (input_node["tap_selector"]) {
            auto tap_selector = input_node["tap_selector"];
            if (!tap_selector.IsMap()) {
                throw PolicyException("'input.tap_selector' is not a map");
            }

            if (tap_selector["all"] && tap_selector["any"]) {
                throw PolicyException("input can have only key 'input.tap_selector.all' or key 'input.tap_selector.any'");
            } else if (!tap_selector["all"] && !tap_selector["any"]) {
                throw PolicyException("missing key 'input.tap_selector.all' or key 'input.tap_selector.any'");
            }

            bool all = true;
            std::string binary_op;
            if (tap_selector["all"]) {
                if (!tap_selector["all"].IsMap()) {
                    throw PolicyException("'input.tap_selector.all' is not a map");
                }
                all = true;
                binary_op = "all";
            } else if (tap_selector["any"] || tap_selector["any"].IsMap()) {
                if (!tap_selector["any"].IsMap()) {
                    throw PolicyException("'input.tap_selector.any' is not a map");
                }
                all = false;
                binary_op = "any";
            }

            bool match = false;
            auto [tap_modules, hm_lock] = _registry->tap_manager()->module_get_all_locked();
            auto policy_ptr = policy.get();
            module_add(std::move(policy));
            try {
                for (auto &[name, mod] : tap_modules) {
                    auto tmod = dynamic_cast<Tap *>(mod.get());
                    if (tmod && tmod->tags_match_selector_yaml(tap_selector[binary_op], all)) {
                        _validate_policy(it->second, policy_name, policy_ptr, tmod);
                        match = true;
                    }
                }
            } catch (PolicyException &e) {
                module_remove(policy_name);
                throw;
            }
            if (!match) {
                module_remove(policy_name);
                spdlog::get("visor")->info("policy [{}]: no tap match found for specified 'input.tap_selector' tags", policy_name);
                throw std::invalid_argument("no tap match found for specified 'input.tap_selector' tags");
            }
            result.push_back(policy_ptr);
        }
    }

    return result;
}

void PolicyManager::_validate_policy(const YAML::Node &policy_yaml, const std::string &policy_name, Policy *policy_ptr, Tap *tap)
{
    auto input_node = policy_yaml["input"];
    // Tap
    std::unique_lock<std::shared_mutex> tap_lock;
    std::string tap_name;
    if (tap == nullptr) {
        tap_name = input_node["tap"].as<std::string>();
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
    } else {
        tap_name = tap->name();
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

    std::string input_stream_module_name = tap->get_input_name(tap_config, tap_filter);

    std::unique_ptr<InputStream> input_stream;
    InputStream *input_ptr = nullptr;
    std::unique_lock<std::shared_mutex> input_lock;
    if (_registry->input_manager()->module_exists(input_stream_module_name)) {
        spdlog::get("visor")->info("policy [{}]: input stream already exists. reusing: {}", policy_name, input_stream_module_name);
        auto result_input = _registry->input_manager()->module_get_locked(input_stream_module_name);
        input_ptr = result_input.module;
        input_lock = std::move(result_input.lock);
    } else {
        // Instantiate stream from tap
        try {
            spdlog::get("visor")->debug("policy [{}]: instantiating Tap: {}", policy_name, tap_name);
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

    InputEventProxy *input_event_proxy = nullptr;
    try {
        input_event_proxy = input_ptr->add_event_proxy(tap_filter);
    } catch (ConfigException &e) {
        throw PolicyException(fmt::format("unable to create event proxy due to invalid input filter config: {}", e.what()));
    }

    // if and only if policy succeeds, we will return this in result set
    policy_ptr->add_tap(tap);
    policy_ptr->add_input_stream(input_ptr);

    // Handler Section

    auto handler_node = policy_yaml["handlers"];
    if (!handler_node || !handler_node.IsMap()) {
        throw PolicyException("missing or invalid handler configuration at key 'handlers'");
    }

    bool handler_sequence = false;
    if (!handler_node["modules"] || (!handler_node["modules"].IsMap() && !handler_node["modules"].IsSequence())) {
        throw PolicyException("missing or invalid handler modules at key 'modules'");
    } else if (handler_node["modules"].IsSequence()) {
        handler_sequence = true;
    }

    policy_ptr->set_modules_sequence(handler_sequence);

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
    window_config.config_set<std::string>("_internal_tap_name", tap_name);

    std::unique_ptr<Policy> input_resources_policy;
    Policy *input_res_policy_ptr{nullptr};
    std::unique_ptr<StreamHandler> resources_module;
    if (input_stream) {
        // create new policy with resources handler for input stream
        input_resources_policy = std::make_unique<Policy>(input_stream_module_name + "-resources");
        input_resources_policy->add_input_stream(input_ptr);
        auto resources_handler_plugin = _registry->handler_plugins().find("input_resources");
        if (resources_handler_plugin != _registry->handler_plugins().end()) {
            resources_module = resources_handler_plugin->second->instantiate(input_stream_module_name + "-resources", input_event_proxy, &window_config, nullptr);
            input_resources_policy->add_module(resources_module.get());
            input_res_policy_ptr = input_resources_policy.get();
        }
    }

    std::vector<std::unique_ptr<StreamHandler>> handler_modules;
    for (YAML::const_iterator h_it = handler_node["modules"].begin(); h_it != handler_node["modules"].end(); ++h_it) {
        auto handler_config = _validate_handler(h_it, policy_name, window_config, handler_sequence);
        std::unique_ptr<StreamHandler> handler_module;
        auto handler_plugin = _registry->handler_plugins().find(handler_config.type);
        auto handler_name = policy_name + "-" + tap_name + "-" + handler_config.name;
        if (!handler_sequence || handler_modules.empty()) {
            handler_module = handler_plugin->second->instantiate(handler_name, input_event_proxy, &handler_config.config, &handler_config.filter);
        } else {
            // for sequence, use only previous handler
            handler_modules.back()->set_event_proxy(input_ptr->create_event_proxy(Configurable()));
            handler_module = handler_plugin->second->instantiate(handler_name, handler_modules.back()->get_event_proxy(), &handler_config.config, &handler_config.filter);
        }
        policy_ptr->add_module(handler_module.get());
        handler_modules.emplace_back(std::move(handler_module));
    }

    // make sure policy starts before committing
    try {
        policy_ptr->start();
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
        if (input_res_policy_ptr) {
            input_res_policy_ptr->stop();
            module_remove(input_res_policy_ptr->name());
        }

        policy_ptr->stop();

        for (auto &m : added_handlers) {
            _registry->handler_manager()->module_remove(m);
        }
        if (!input_ptr->policies_count()) {
            _registry->input_manager()->module_remove(input_stream_module_name);
        }

        // at this point no outside reference is held to the modules so they will destruct
        throw PolicyException(fmt::format("policy [{}] creation failed (handler: {}): {}", e.name(), policy_name, e.what()));
    }

    // success
    if (input_res_policy_ptr) {
        input_ptr->add_policy(input_res_policy_ptr);
    }
    input_ptr->add_policy(policy_ptr);
}

PolicyManager::HandlerData PolicyManager::_validate_handler(const YAML::const_iterator &hander_iterator, const std::string &policy_name, Config &window_config, bool sequence)
{
    // Per handler
    const auto it_module = [&]() -> const YAML::Node {
        return sequence ? *hander_iterator : hander_iterator->second;
    }();

    HandlerData handler;
    if (sequence) {
        if (!it_module.begin()->first.IsScalar()) {
            throw PolicyException("expecting handler module identifier");
        }
        handler.name = it_module.begin()->first.as<std::string>();
    } else {
        if (!hander_iterator->first.IsScalar()) {
            throw PolicyException("expecting handler module identifier");
        }
        handler.name = hander_iterator->first.as<std::string>();
    }

    if (!it_module.IsMap()) {
        throw PolicyException("expecting Handler configuration map");
    }

    auto module = YAML::Clone(it_module);
    if (!module["type"] || !module["type"].IsScalar()) {
        module = module[handler.name];
        if (!module["type"] || !module["type"].IsScalar()) {
            throw PolicyException("missing or invalid stream handler type at key 'type'");
        }
    }

    handler.type = module["type"].as<std::string>();
    auto handler_plugin = _registry->handler_plugins().find(handler.type);
    if (handler_plugin == _registry->handler_plugins().end()) {
        throw PolicyException(fmt::format("Policy '{}' requires stream handler type '{}' which is not available", policy_name, handler.type));
    }

    if (module["filter"]) {
        if (!module["filter"].IsMap()) {
            throw PolicyException("stream handler filter configuration is not a map");
        }
        try {
            handler.filter.config_set_yaml(module["filter"]);
        } catch (ConfigException &e) {
            throw PolicyException(fmt::format("invalid stream handler filter config for handler '{}': {}", handler.name, e.what()));
        }
    }

    if (auto it_global = _global_handler_config.find(handler.type); it_global != _global_handler_config.end()) {
        handler.config.config_merge(*it_global->second);
    }
    if (module["config"]) {
        if (!module["config"].IsMap()) {
            throw PolicyException("stream handler configuration is not a map");
        }
        try {
            handler.config.config_set_yaml(module["config"]);
        } catch (ConfigException &e) {
            throw PolicyException(fmt::format("invalid stream handler config for handler '{}': {}", handler.name, e.what()));
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
            handler_metrics.config_set_yaml(module["metric_groups"]);
        } catch (ConfigException &e) {
            throw PolicyException(fmt::format("invalid stream handler metrics for handler '{}': {}", handler.name, e.what()));
        }
    }
    spdlog::get("visor")->info("policy [{}]: instantiating Handler {} of type {}", policy_name, handler.name, handler.type);
    // note, currently merging the handler config with the window config. do they need to be separate?
    handler.config.config_merge(window_config);
    handler.filter.config_merge(handler_metrics);

    return handler;
}

void PolicyManager::remove_policy(const std::string &name)
{
    std::unique_lock lock(_map_mutex);
    if (_map.count(name) == 0) {
        throw ModuleException(name, fmt::format("module name '{}' does not exist", name));
    }

    auto policy = _map[name].get();
    std::map<std::string, InputStream *> input_stream;
    for (const auto &input : policy->input_stream()) {
        input_stream[input->name()] = input;
    }

    std::vector<std::string> module_names;
    for (const auto &mod : policy->modules()) {
        module_names.push_back(mod->name());
    }
    policy->stop();

    for (const auto &name : module_names) {
        _registry->handler_manager()->module_remove(name);
    }

    for (const auto &input : input_stream) {
        if (input.second->policies_count() == 1) {
            // if there is only one policy left on the input stream, and that policy is the input resources policy, then remove it
            auto input_resources_name = input.first + "-resources";
            if (name != input_resources_name && _map.count(input_resources_name) != 0) {
                auto resources_policy = _map[input_resources_name].get();
                resources_policy->stop();
                _registry->handler_manager()->module_remove(input_resources_name);
                _map.erase(input_resources_name);
            }
        }

        if (!input.second->policies_count()) {
            _registry->input_manager()->module_remove(input.first);
        }
    }

    _map.erase(name);
}
void Policy::info_json(json &j) const
{
    for (auto &input : _input_streams) {
        input->info_json(j["input"][input->name()]);
    }
    for (auto &mod : _modules) {
        mod->info_json(j["modules"][mod->name()]);
    }
}
void Policy::start()
{
    if (_running) {
        return;
    }
    assert(_input_streams.size());
    spdlog::get("visor")->info("policy [{}]: starting", _name);
    for (auto &mod : _modules) {
        spdlog::get("visor")->debug("policy [{}]: starting handler instance: {}", _name, mod->name());
        mod->start();
    }
    // start input stream _after_ modules, since input stream will create a new thread and we need to catch any startup errors
    // from handlers in the same thread we are starting the policy from
    for (auto &input : _input_streams) {
        spdlog::get("visor")->debug("policy [{}]: starting input instance: {}", _name, input->name());
        input->start();
    }
    _running = true;
}
void Policy::stop()
{
    if (!_running) {
        return;
    }
    spdlog::get("visor")->info("policy [{}]: stopping", _name);
    for (auto &input : _input_streams) {
        if (input->running()) {
            if (input->policies_count() <= 1) {
                spdlog::get("visor")->debug("policy [{}]: stopping input instance: {}", _name, input->name());
                input->stop();
            } else {
                spdlog::get("visor")->info("policy [{}]: input instance {} not stopped because it is in use by another policy.", _name, input->name());
            }
        }
        input->remove_policy(this);
    }
    for (auto &mod : _modules) {
        if (mod->running()) {
            spdlog::get("visor")->debug("policy [{}]: stopping handler instance: {}", _name, mod->name());
            mod->stop();
        }
    }
    _running = false;
}
}
