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
            throw TapException("expecting tap identifier");
        }
        auto tap_name = it->first.as<std::string>();
        spdlog::get("visor")->info("tap [{}]: parsing", tap_name);
        if (!it->second.IsMap()) {
            throw TapException("expecting tap configuration map");
        }
        if (!it->second["input_type"] || !it->second["input_type"].IsScalar()) {
            throw TapException("missing or invalid tap type key 'input_type'");
        }
        auto input_type = it->second["input_type"].as<std::string>();

        auto input_plugin = _registry->input_plugins().find(input_type);
        if (input_plugin == _registry->input_plugins().end()) {
            if (strict) {
                throw TapException(fmt::format("Tap '{}' requires input stream type '{}' which is not available", tap_name, input_type));
            } else {
                spdlog::get("visor")->warn("Tap '{}' requires input stream type '{}' which is not available; skipping", tap_name, input_type);
                continue;
            }
        }

        auto tap_module = std::make_unique<Tap>(tap_name, input_plugin->second.get());

        if (it->second["config"]) {
            if (!it->second["config"].IsMap()) {
                throw TapException("tap configuration is not a map");
            }
            tap_module->config_set_yaml(it->second["config"]);
        }

        if (it->second["tags"]) {
            if (!it->second["tags"].IsMap()) {
                throw TapException("tap tags is not a map");
            }
            tap_module->tags_set_yaml(it->second["tags"]);
        }

        // will throw if it already exists. nothing else to clean up
        module_add(std::move(tap_module));

        spdlog::get("visor")->info("tap [{}]: loaded, type {}", tap_name, input_type);
    }
}

std::string Tap::get_input_name(const Configurable &config, const Configurable &filter)
{
    Config c;
    c.config_merge(dynamic_cast<const Configurable &>(*this));
    c.config_merge(config);
    return _input_plugin->generate_input_name(name(), c, filter);
}

std::unique_ptr<InputStream> Tap::instantiate(const Configurable *config, const Configurable *filter, std::string input_name)
{
    Config c;
    c.config_merge(dynamic_cast<const Configurable &>(*this));
    c.config_merge(*config);
    auto module = _input_plugin->instantiate(input_name, &c, filter);

    return module;
}

bool Tap::tags_match_selector_yaml(const YAML::Node &tag_yaml, bool all)
{
    bool any_match = false;
    for (YAML::const_iterator it = tag_yaml.begin(); it != tag_yaml.end(); ++it) {
        if (!it->second.IsScalar()) {
            throw TapException(fmt::format("tag key '{}' must have scalar value", it->first));
        }

        auto key = it->first.as<std::string>();
        if (!_tags->config_exists(key)) {
            if (all) {
                return false;
            } else {
                continue;
            }
        }

        // the yaml library doesn't discriminate between scalar types, so we have to do that ourselves
        auto value = it->second.as<std::string>();
        if (std::regex_match(value, std::regex("[0-9]+"))) {
            if (_tags->config_get<uint64_t>(key) == it->second.as<uint64_t>()) {
                any_match = true;
            } else if (all) {
                return false;
            }

        } else if (std::regex_match(value, std::regex("true|false", std::regex_constants::icase))) {
            if (_tags->config_get<bool>(key) == it->second.as<bool>()) {
                any_match = true;
            } else if (all) {
                return false;
            }
        } else {
            if (_tags->config_get<std::string>(key) == value) {
                any_match = true;
            } else if (all) {
                return false;
            }
        }
    }

    return any_match;
}

}
