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
        return load(node["visor"]["policies"], true);
    } else {
        throw PolicyException("no policies found in schema");
    }
}

// needs to be thread safe and transactional: any errors mean resources get cleaned up with no side effects
std::vector<Policy *> PolicyManager::load(const YAML::Node &policy_yaml, bool single)
{
    assert(policy_yaml.IsMap());
    assert(spdlog::get("visor"));

    if (single && policy_yaml.size() > 1) {
        throw PolicyException(fmt::format("only a single policy expected but got {}", policy_yaml.size()));
    }

    std::vector<Policy *> result;
    for (YAML::const_iterator it = policy_yaml.begin(); it != policy_yaml.end(); ++it) {

        // serialized policy loads
        std::unique_lock lock(_load_mutex);

        auto policy_name = _get_policy_name(it);
        // Input Section
        auto input_node = it->second["input"];
        auto [input_config, input_filter] = _registry->input_manager()->get_config_and_filter(input_node);
        // Handler Default Section
        auto handler_node = it->second["handlers"];
        auto [window_config, handler_sequence] = _registry->handler_manager()->get_default_configuration(handler_node);

        // tap manager ensures that at least one tap is returned, if not it throws
        auto taps_name = _registry->tap_manager()->get_input_taps_name(input_node);

        // create policy
        auto policy = std::make_unique<Policy>(policy_name);
        auto policy_ptr = policy.get();
        policy_ptr->set_modules_sequence(handler_sequence);

        std::vector<std::string> added_inputs;
        std::vector<std::string> added_handlers;
        try {
            for (const auto &tap_name : taps_name) {
                auto [tap, tap_lock] = _registry->tap_manager()->module_get_locked(tap_name);
                policy_ptr->add_tap(tap);
                // ensure tap input type matches policy input tap
                if (input_node["input_type"].as<std::string>() != tap->input_plugin()->plugin()) {
                    throw PolicyException(fmt::format("input_type for policy specified tap '{}' doesn't match tap's defined input type: {}/{}", tap_name, input_node["input_type"].as<std::string>(), tap->input_plugin()->plugin()));
                }
                // handler internal config
                window_config.config_set<std::string>("_internal_tap_name", tap_name);

                std::string input_stream_name = tap->get_input_name(input_config, input_filter);
                if (!_registry->input_manager()->module_exists(input_stream_name)) {
                    try {
                        spdlog::get("visor")->info("policy [{}]: creating input stream: {}", policy_name, input_stream_name);
                        _registry->input_manager()->module_add(tap->instantiate(&input_config, &input_filter, input_stream_name));
                        added_inputs.push_back(input_stream_name);
                    } catch (std::runtime_error &e) {
                        throw PolicyException(fmt::format("unable to instantiate tap '{}': {}", tap_name, e.what()));
                    }
                } else {
                    spdlog::get("visor")->debug("policy [{}]: input stream already exists. reusing: {}", policy_name, input_stream_name);
                }

                auto [input_ptr, input_lock] = _registry->input_manager()->module_get_locked(input_stream_name);
                InputEventProxy *input_event_proxy = input_ptr->add_event_proxy(input_filter);
                policy_ptr->add_input_stream(input_ptr);

                std::vector<std::unique_ptr<StreamHandler>> handler_modules;
                for (YAML::const_iterator h_it = handler_node["modules"].begin(); h_it != handler_node["modules"].end(); ++h_it) {
                    auto handler_config = _registry->handler_manager()->validate_handler(h_it, policy_name, window_config, handler_sequence);
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

                for (auto &m : handler_modules) {
                    auto hname = m->name();
                    _registry->handler_manager()->module_add(std::move(m));
                    added_handlers.push_back(hname);
                }

                // success
                input_ptr->add_policy(policy_ptr);
            }

            for (auto &p : added_inputs) {
                auto [input_ptr, input_lock] = _registry->input_manager()->module_get_locked(p);
                added_handlers.push_back(create_resources_policy(input_ptr, window_config));
            }

        } catch (std::runtime_error &e) {
            // failed to create policy
            for (auto &m : added_handlers) {
                _registry->handler_manager()->module_remove(m);
            }
            for (auto &p : added_inputs) {
                _registry->input_manager()->module_remove(p);
            }
            throw;
        }

        try {
            policy_ptr->start();
            module_add(std::move(policy));
        } catch (std::runtime_error &e) {
            for (auto &m : added_handlers) {
                _registry->handler_manager()->module_remove(m);
            }
            for (auto &p : added_inputs) {
                _registry->input_manager()->module_remove(p);
            }
            throw PolicyException(fmt::format("policy [{}] failed to start: {}", policy_name, e.what()));
        }

        result.push_back(policy_ptr);
    }

    return result;
}

std::string PolicyManager::create_resources_policy(InputStream *input, const Config &window_config)
{
    auto resources_handler_plugin = _registry->handler_plugins().find("input_resources");
    if (resources_handler_plugin == _registry->handler_plugins().end()) {
        spdlog::get("visor")->info("input_resources handler not available, not able to create input resources policy for input stream: {}", input->name());
        return std::string();
    }

    // create new policy with resources handler for input stream
    auto resources_policy = std::make_unique<Policy>(input->name() + "-resources");
    auto resources_policy_ptr = resources_policy.get();
    resources_policy->add_input_stream(input);

    auto resources_module = resources_handler_plugin->second->instantiate(input->name() + "-resources", input->add_event_proxy(Configurable()), &window_config, nullptr);
    auto module_name = resources_module->name();
    resources_policy->add_module(resources_module.get());

    try {
        resources_policy->start();
        module_add(std::move(resources_policy));
    } catch (std::runtime_error &e) {
        throw PolicyException(fmt::format("internal policy [{}] failed to start: {}", resources_policy->name(), e.what()));
    }

    _registry->handler_manager()->module_add(std::move(resources_module));
    // success
    input->add_policy(resources_policy_ptr);
    return module_name;
}

std::string PolicyManager::_get_policy_name(YAML::const_iterator it)
{
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
    return policy_name;
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

    for (const auto &mod_name : module_names) {
        _registry->handler_manager()->module_remove(mod_name);
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
    for (auto &tap : _taps) {
        tap->info_json(j["taps"][tap->name()]);
    }
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
