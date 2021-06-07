/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Policies.h"
#include <algorithm>
#include <fmt/core.h>
#include <spdlog/spdlog.h>

void visor::PolicyManager::load(const YAML::Node &policy_yaml, bool strict)
{
    assert(policy_yaml.IsMap());
    assert(spdlog::get("visor"));

    auto input_plugins = _input_plugin_registry->aliasList();

    for (YAML::const_iterator it = policy_yaml.begin(); it != policy_yaml.end(); ++it) {
        if (!it->first.IsScalar()) {
            throw ConfigException("expecting policy identifier");
        }
        auto policy_name = it->first.as<std::string>();
        spdlog::get("visor")->info("loading Policy: {}", policy_name);
        if (!it->second.IsMap()) {
            throw ConfigException("expecting policy configuration map");
        }
        if (!it->second["input"] || !it->second["input"].IsScalar()) {
            throw ConfigException("missing or invalid policy input stream configuration at key 'input'");
        }
        auto input_type = it->second["input"].as<std::string>();
        if (std::find(input_plugins.begin(), input_plugins.end(), input_type) == input_plugins.end()) {
            if (strict) {
                throw ConfigException(fmt::format("Policy '{}' requires input stream type '{}' which is not available", policy_name, input_type));
            } else {
                spdlog::get("visor")->warn("Policy '{}' requires input stream type '{}' which is not available; skipping", policy_name, input_type);
                continue;
            }
        }

        auto policy_module = std::make_unique<Policy>(policy_name, input_type);

        if (it->second["config"]) {
            if (!it->second["config"].IsMap()) {
                throw ConfigException("tap configuration is not a map");
            }
            policy_module->config_set_yaml(it->second["config"]);
        }

        module_add(std::move(policy_module));
    }
}
