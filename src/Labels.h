/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractManager.h"
#include "AbstractModule.h"
#include "AbstractPlugin.h"
#include "Configurable.h"
#include <yaml-cpp/yaml.h>

namespace visor {

class Policy;

class Label : public AbstractModule
{
    std::string _label_value;

public:
    Label(const std::string &name, const std::string &value)
        : AbstractModule(name)
        , _label_value(value)
    {
    }

    const std::string &value() const
    {
        return _label_value;
    }

    void info_json(json &j) const override
    {
        j[_name] = _label_value;
    }
};

class LabelManager : public AbstractManager<Label>
{

    const CoreRegistry *_registry;

public:
    LabelManager(const CoreRegistry *registry)
        : _registry(registry)
    {
    }

    virtual ~LabelManager()
    {
    }

    void load(const YAML::Node &label_yaml);
};

}