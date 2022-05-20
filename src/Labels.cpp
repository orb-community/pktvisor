/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Labels.h"
#include <fmt/core.h>
#include <spdlog/spdlog.h>

namespace visor {

void LabelManager::load(const YAML::Node &label_yaml)
{
    assert(label_yaml.IsMap());
    assert(spdlog::get("visor"));

    for (YAML::const_iterator it = label_yaml.begin(); it != label_yaml.end(); ++it) {
        if (!it->first.IsScalar()) {
            throw ConfigException("expecting label identifier");
        }
        auto label_name = it->first.as<std::string>();
        spdlog::get("visor")->info("label [{}]: parsing", label_name);
        if (!it->second.IsScalar()) {
            throw ConfigException("expecting label value");
        }
        auto label_value = it->second.as<std::string>();

        auto label_module = std::make_unique<Label>(label_name, label_value);

        // will throw if it already exists. nothing else to clean up
        module_add(std::move(label_module));

        spdlog::get("visor")->info("label [{}]: added, value {}", label_name, label_value);
    }
}

}
