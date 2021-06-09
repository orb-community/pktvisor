/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Taps.h"
#include "CoreRegistry.h"
#include "InputStream.h"
#include "Policies.h"
#include <algorithm>
#include <fmt/core.h>
#include <spdlog/spdlog.h>

namespace visor {

// needs to be thread safe and transactional: any errors mean resources get cleaned up with no side effects
void TapManager::load(const YAML::Node &tap_yaml, bool strict)
{
    assert(tap_yaml.IsMap());
    assert(spdlog::get("visor"));

    for (YAML::const_iterator it = tap_yaml.begin(); it != tap_yaml.end(); ++it) {
        if (!it->first.IsScalar()) {
            throw ConfigException("expecting tap identifier");
        }
        auto tap_name = it->first.as<std::string>();
        spdlog::get("visor")->info("{}: loading Tap", tap_name);
        if (!it->second.IsMap()) {
            throw ConfigException("expecting tap configuration map");
        }
        if (!it->second["input_type"] || !it->second["input_type"].IsScalar()) {
            throw ConfigException("missing or invalid tap type key 'input_type'");
        }
        auto input_type = it->second["input_type"].as<std::string>();

        auto input_plugin = _registry->input_plugins().find(input_type);
        if (input_plugin == _registry->input_plugins().end()) {
            if (strict) {
                throw ConfigException(fmt::format("Tap '{}' requires input stream type '{}' which is not available", tap_name, input_type));
            } else {
                spdlog::get("visor")->warn("Tap '{}' requires input stream type '{}' which is not available; skipping", tap_name, input_type);
                continue;
            }
        }

        auto tap_module = std::make_unique<Tap>(tap_name, input_plugin->second.get());

        if (it->second["config"]) {
            if (!it->second["config"].IsMap()) {
                throw ConfigException("tap configuration is not a map");
            }
            tap_module->config_set_yaml(it->second["config"]);
        }

        // will throw if it already exists. nothing else to clean up
        module_add(std::move(tap_module));
    }
}

std::unique_ptr<InputStream> Tap::instantiate(Policy *policy, const Configurable *filter_config)
{
    Config c;
    c.config_merge(dynamic_cast<const Configurable &>(*this));
    c.config_merge(*filter_config);
    auto module = _input_plugin->instantiate(_name + "_" + policy->name(), &c);
    module->set_policy(policy);
    return module;
}

}
