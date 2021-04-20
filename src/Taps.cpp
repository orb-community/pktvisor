/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Taps.h"
#include <algorithm>
#include <fmt/core.h>
#include <spdlog/spdlog.h>

void visor::TapManager::load(const YAML::Node &tap_yaml, bool strict)
{
    assert(tap_yaml.IsMap());

    auto input_plugins = _input_plugin_registry->aliasList();

    for (YAML::const_iterator it = tap_yaml.begin(); it != tap_yaml.end(); ++it) {
        if (!it->first.IsScalar()) {
            throw ConfigException("expecting tap identifier");
        }
        auto tap_name = it->first.as<std::string>();
        spdlog::get("pktvisor")->info("loading Tap: {}", tap_name);
        if (!it->second.IsMap()) {
            throw ConfigException("expecting tap configuration map");
        }
        if (!it->second["type"] || !it->second["type"].IsScalar()) {
            throw ConfigException("missing or invalid tap input stream 'type'");
        }
        auto tap_type = it->second["type"].as<std::string>();
        if (std::find(input_plugins.begin(), input_plugins.end(), tap_type) == input_plugins.end()) {
            if (strict) {
                throw ConfigException(fmt::format("Tap '{}' requires input stream type '{}' which is not available", tap_name, tap_type));
            } else {
                spdlog::get("pktvisor")->warn("Tap '{}' requires input stream type '{}' which is not available; skipping", tap_name, tap_type);
                continue;
            }
        }

        auto tap_module = std::make_unique<Tap>(tap_name);

        if (it->second["config"]) {
            if (!it->second["config"].IsMap()) {
                throw ConfigException("tap configuration is not a map");
            }
            tap_module->config_set_yaml(it->second["config"]);
        }

        module_add(std::move(tap_module));
    }
}
