/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Taps.h"
#include <spdlog/spdlog.h>

void visor::TapManager::load(const YAML::Node &tap_yaml)
{
    assert(tap_yaml.IsMap());
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
        if (!_input_manager->module_exists(tap_type)) {
            spdlog::get("pktvisor")->warn("Tap '{}' requires input stream type '{}' which is not available; skipping", tap_name, tap_type);
            continue;
        }
    }
}
