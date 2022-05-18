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

class Tag : public AbstractModule
{
    std::string _tag_value;

public:
    Tag(const std::string &name, const std::string &value)
        : AbstractModule(name)
        , _tag_value(value)
    {
    }

    const std::string &value() const
    {
        return _tag_value;
    }

    void info_json(json &j) const override
    {
        j[_name] = _tag_value;
    }
};

class TagManager : public AbstractManager<Tag>
{

    const CoreRegistry *_registry;

public:
    TagManager(const CoreRegistry *registry)
        : _registry(registry)
    {
    }

    virtual ~TagManager()
    {
    }

    void load(const YAML::Node &tag_yaml);
};

}