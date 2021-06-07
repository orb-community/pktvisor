/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractManager.h"
#include "AbstractModule.h"
#include "Configurable.h"
#include "InputModulePlugin.h"
#include "Taps.h"
#include <yaml-cpp/yaml.h>

namespace visor {

class PolicyException : public std::runtime_error
{
public:
    explicit PolicyException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

class Policy : public AbstractModule
{

    std::string _tap_name;

    YAML::Node _tap_filter;

public:
    Policy(const std::string &name, const std::string &tap_name)
        : AbstractModule(name)
        , _tap_name(tap_name)
        , _tap_filter(YAML::NodeType::Map)
    {
    }

    const YAML::Node &tap_filter() const
    {
        return _tap_filter;
    }

    void set_tap_filter(const YAML::Node &n)
    {
        _tap_filter = n;
    }

    void apply(CoreRegistry *registry);

    void info_json(json &j) const override
    {
        j["tap_name"] = _tap_name;
        config_json(j["config"]);
    }
};

class PolicyManager : public AbstractManager<Policy>
{

    const InputPluginRegistry *_input_plugin_registry;
    const HandlerPluginRegistry *_handler_plugin_registry;

public:
    PolicyManager(const InputPluginRegistry *inputManager, const HandlerPluginRegistry *handlerManager)
        : _input_plugin_registry(inputManager)
        , _handler_plugin_registry(handlerManager)
    {
    }

    virtual ~PolicyManager()
    {
    }

    void load(const YAML::Node &tap_yaml, bool strict);
};

}