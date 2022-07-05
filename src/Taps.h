/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractManager.h"
#include "AbstractModule.h"
#include "Configurable.h"
#include "InputModulePlugin.h"
#include <yaml-cpp/yaml.h>

namespace visor {

class InputStream;
class Policy;

class Tap : public AbstractModule
{

    InputModulePlugin *_input_plugin;

public:
    Tap(const std::string &name, InputModulePlugin *input_plugin)
        : AbstractModule(name)
        , _input_plugin(input_plugin)
    {
        assert(input_plugin);
    }

    std::string get_input_name(const Configurable &config, const Configurable &filter);

    std::unique_ptr<InputStream> instantiate(const Configurable *config, const Configurable *filter, std::string input_name);

    const InputModulePlugin *input_plugin() const
    {
        return _input_plugin;
    }

    void info_json(json &j) const override
    {
        j["input_type"] = _input_plugin->plugin();
        j["interface"] = _input_plugin->pluginInterface();
        config_json(j["config"]);
    }
};

class TapManager : public AbstractManager<Tap>
{

    const CoreRegistry *_registry;

public:
    TapManager(const CoreRegistry *registry)
        : _registry(registry)
    {
    }

    virtual ~TapManager()
    {
    }

    void load(const YAML::Node &tap_yaml, bool strict);
};

}