/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Policies.h"
#include "CoreRegistry.h"
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
        spdlog::get("visor")->info("loading Policy: {}", policy_name);
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
        try {
            input_stream = tap->instantiate(policy.get(), &tap_filter);
        } catch (std::runtime_error &e) {
            throw PolicyException(fmt::format("unable to instantiate tap {}: {}", tap_name, e.what()));
        }
        policy->set_input_stream(input_stream.get());

        // Make modules visible in registry
        try {
            module_add(std::move(policy));
            _registry->input_manager()->module_add(std::move(input_stream));
        } catch (ModuleException &e) {
            throw PolicyException(fmt::format("unable to add policy {}: {}", policy_name, e.what()));
        }
    }
}

void Policy::info_json(json &j) const
{
    config_json(j["config"]);
    for (auto &mod : _modules) {
    }
}
void Policy::start()
{
    assert(_tap);
    assert(_input_stream);
    _input_stream->start();
}
void Policy::stop()
{
    _input_stream->stop();
}

}