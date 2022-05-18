/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Tags.h"
#include <fmt/core.h>
#include <spdlog/spdlog.h>

namespace visor {

void TagManager::load(const YAML::Node &tag_yaml)
{
    assert(tag_yaml.IsMap());
    assert(spdlog::get("visor"));

    for (YAML::const_iterator it = tag_yaml.begin(); it != tag_yaml.end(); ++it) {
        if (!it->first.IsScalar()) {
            throw ConfigException("expecting tag identifier");
        }
        auto tag_name = it->first.as<std::string>();
        spdlog::get("visor")->info("tag [{}]: parsing", tag_name);
        if (!it->second.IsScalar()) {
            throw ConfigException("expecting tag value");
        }
        auto tag_value = it->second.as<std::string>();

        auto tag_module = std::make_unique<Tag>(tag_name, tag_value);

        // will throw if it already exists. nothing else to clean up
        module_add(std::move(tag_module));

        spdlog::get("visor")->info("tag [{}]: added, value {}", tag_name, tag_value);
    }
}

}
