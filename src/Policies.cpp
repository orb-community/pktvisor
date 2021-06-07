/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Policies.h"
#include "CoreRegistry.h"
#include "InputStreamManager.h"
#include "Taps.h"
#include <algorithm>
#include <spdlog/spdlog.h>

namespace visor {

void PolicyManager::load(const YAML::Node &policy_yaml, bool strict)
{
    assert(policy_yaml.IsMap());
    assert(spdlog::get("visor"));

    auto input_plugins = _input_plugin_registry->aliasList();
    auto handler_plugins = _handler_plugin_registry->aliasList();

    for (YAML::const_iterator it = policy_yaml.begin(); it != policy_yaml.end(); ++it) {
        if (!it->first.IsScalar()) {
            throw ConfigException("expecting policy identifier");
        }
        auto policy_name = it->first.as<std::string>();
        spdlog::get("visor")->info("loading Policy: {}", policy_name);
        if (!it->second.IsMap()) {
            throw ConfigException("expecting policy configuration map");
        }
        if (!it->second["input"] || !it->second["input"].IsMap()) {
            throw ConfigException("missing or invalid policy input stream configuration at key 'input'");
        }

        auto input_node = it->second["input"];
        if (!input_node["tap"] || !input_node["tap"].IsScalar()) {
            throw ConfigException("missing or invalid tap at key 'tap'");
        }

        auto policy_module = std::make_unique<Policy>(policy_name, input_node["tap"].as<std::string>());

        if (input_node["filter"]) {
            if (!input_node["filter"].IsMap()) {
                throw ConfigException("input filter configuration is not a map");
            }
            policy_module->set_tap_filter(input_node["filter"]);
        }

        module_add(std::move(policy_module));
    }
}

void Policy::apply(CoreRegistry *registry)
{
    // get Tap* by name
    // call the instantiate method on it which returns InputStream*, pass argument tap_filter
    //
}

}