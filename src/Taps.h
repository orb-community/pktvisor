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

class Tap : public AbstractModule
{

    std::string _input_type;

public:
    Tap(const std::string &name, const std::string &input_type)
        : AbstractModule(name)
        , _input_type(input_type)
    {
    }

    void info_json(json &j) const override
    {
        j["input_type"] = _input_type;
        config_json(j["config"]);
    }
};

class TapManager : public AbstractManager<Tap>
{

    const InputPluginRegistry *_input_plugin_registry;

public:
    TapManager(const InputPluginRegistry *inputManager)
        : _input_plugin_registry(inputManager)
    {
    }

    virtual ~TapManager()
    {
    }

    void load(const YAML::Node &tap_yaml, bool strict);
};

}