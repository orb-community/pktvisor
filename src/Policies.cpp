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

// needs to be thread safe and transactional: any errors mean resources get cleaned up with no side effects
void PolicyManager::load(const YAML::Node &policy_yaml)
{
    assert(policy_yaml.IsMap());
    assert(spdlog::get("visor"));

    auto input_plugins = _registry->input_plugin_registry()->aliasList();
    //auto handler_plugins = _handler_plugin_registry->aliasList();

    for (YAML::const_iterator it = policy_yaml.begin(); it != policy_yaml.end(); ++it) {

        // serialized policy loads
        std::unique_lock lock(_load_mutex);

        // Basic Structure
        if (!it->first.IsScalar()) {
            throw PolicyException("expecting policy identifier");
        }
        auto policy_name = it->first.as<std::string>();
        spdlog::get("visor")->info("{}: loading Policy", policy_name);
        if (!it->second.IsMap()) {
            throw PolicyException("expecting policy configuration map");
        }

        // Input Section
        if (!it->second["input"] || !it->second["input"].IsMap()) {
            throw PolicyException("missing or invalid policy input stream configuration at key 'input'");
        }
        auto input_node = it->second["input"];
        if (!input_node["tap"] || !input_node["tap"].IsScalar()) {
            throw PolicyException("missing or invalid tap at key 'tap'");
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

        // Tap Input Filter
        Config tap_filter;
        if (input_node["filter"]) {
            if (!input_node["filter"].IsMap()) {
                throw PolicyException("input filter configuration is not a map");
            }
            try {
                tap_filter.config_set_yaml(input_node["filter"]);
            } catch (ConfigException &e) {
                throw PolicyException(fmt::format("invalid input filter config for tap '{}': {}", tap_name, e.what()));
            }
        }

        // Create Policy
        auto policy = std::make_unique<Policy>(policy_name, tap);

        // Instantiate stream from tap
        std::unique_ptr<InputStream> input_stream;
        std::string input_stream_module_name;
        try {
            spdlog::get("visor")->info("{}: instantiating Tap: {}", policy_name, tap_name);
            input_stream = tap->instantiate(policy.get(), &tap_filter);
            input_stream_module_name = input_stream->name();
        } catch (std::runtime_error &e) {
            throw PolicyException(fmt::format("unable to instantiate tap {}: {}", tap_name, e.what()));
        }
        policy->set_input_stream(input_stream.get());

        // Handler Section
        if (!it->second["handlers"] || !it->second["handlers"].IsMap()) {
            throw PolicyException("missing or invalid handler configuration at key 'handlers'");
        }
        auto handler_node = it->second["handlers"];
        if (!handler_node["modules"] || !handler_node["modules"].IsMap()) {
            throw PolicyException("missing or invalid handler modules at key 'modules'");
        }
        std::vector<std::unique_ptr<StreamHandler>> handler_modules;
        for (YAML::const_iterator h_it = handler_node["modules"].begin(); h_it != handler_node["modules"].end(); ++h_it) {
            // Per handler
            if (!h_it->first.IsScalar()) {
                throw PolicyException("expecting handler module identifier");
            }
            auto handler_module_name = h_it->first.as<std::string>();
            if (!h_it->second.IsMap()) {
                throw PolicyException("expecting Handler configuration map");
            }
            if (!h_it->second["type"] || !h_it->second["type"].IsScalar()) {
                throw PolicyException("missing or invalid stream handler type at key 'type'");
            }
            auto handler_module_type = h_it->second["type"].as<std::string>();
            auto handler_plugin = _registry->handler_plugins().find(handler_module_type);
            if (handler_plugin == _registry->handler_plugins().end()) {
                throw PolicyException(fmt::format("Policy '{}' requires stream handler type '{}' which is not available", policy_name, handler_module_type));
            }
            Config handler_config;
            if (h_it->second["config"]) {
                if (!h_it->second["config"].IsMap()) {
                    throw PolicyException("stream handler configuration is not a map");
                }
                try {
                    handler_config.config_set_yaml(h_it->second["config"]);
                } catch (ConfigException &e) {
                    throw PolicyException(fmt::format("invalid stream handler config for handler '{}': {}", handler_module_name, e.what()));
                }
            }
            spdlog::get("visor")->info("{}: instantiating Handler {} of type {}", policy_name, handler_module_name, handler_module_type);
            handler_modules.emplace_back(handler_plugin->second->instantiate(handler_module_name, input_stream.get(), &handler_config));
        }

        // Make modules visible in registry
        // If the modules created above go out of scope before this step, they will destruct so the key is to make sure
        // roll back during exception ensures no modules have been added to any of the managers
        try {
            module_add(std::move(policy));
        } catch (ModuleException &e) {
            throw PolicyException(fmt::format("policy creation failed (policy) {}: {}", policy_name, e.what()));
        }
        try {
            _registry->input_manager()->module_add(std::move(input_stream));
        } catch (ModuleException &e) {
            // note that if this call excepts, we are in an unknown state and the exception will propagate
            module_remove(policy_name);
            throw PolicyException(fmt::format("policy creation failed (input) {}: {}", policy_name, e.what()));
        }
        std::vector<std::string> added_handlers;
        try {
            for (auto &m : handler_modules) {
                auto hname = m->name();
                _registry->handler_manager()->module_add(std::move(m));
                // if it did not except, add it to the list for rollback upon exception
                added_handlers.push_back(hname);
            }
        } catch (ModuleException &e) {
            // note that if any of these calls except, we are in an unknown state and the exception will propagate
            // nothing needs to be stopped because it was not started
            module_remove(policy_name);
            _registry->input_manager()->module_remove(input_stream_module_name);
            for (auto &m : added_handlers) {
                _registry->handler_manager()->module_remove(m);
            }
            // at this point no outside reference is held to the modules so they will destruct
            throw PolicyException(fmt::format("policy creation failed (handler: {}) {}: {}", e.name(), policy_name, e.what()));
        }
    }
}

void Policy::info_json(json &j) const
{
    config_json(j["config"]);
    /*
    for (auto &mod : _modules) {
    }
     */
}
void Policy::start()
{
    assert(_tap);
    assert(_input_stream);
    spdlog::get("visor")->info("{}: starting", _name);
    _input_stream->start();
}
void Policy::stop()
{
    _input_stream->stop();
}

}