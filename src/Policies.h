/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractManager.h"
#include "AbstractModule.h"
#include "Configurable.h"
#include "HandlerModulePlugin.h"
#include "InputModulePlugin.h"
#include "Taps.h"
#include <vector>
#include <yaml-cpp/yaml.h>

namespace visor {

class CoreRegistry;

class PolicyException : public std::runtime_error
{
public:
    explicit PolicyException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

class Policy : public AbstractRunnableModule
{

    Tap *_tap;
    InputStream *_input_stream;
    std::vector<AbstractRunnableModule *> _modules;

public:
    Policy(const std::string &name, Tap *tap)
        : AbstractRunnableModule(name)
        , _tap(tap)
        , _input_stream(nullptr)
    {
    }

    std::string schema_key() const override
    {
        return "policy";
    }

    void set_input_stream(InputStream *input_stream)
    {
        _input_stream = input_stream;
    }

    const InputStream *input_stream() const
    {
        return _input_stream;
    }

    void add_module(AbstractRunnableModule *m)
    {
        _modules.push_back(m);
    }

    const std::vector<AbstractRunnableModule *> &modules()
    {
        return _modules;
    }

    // life cycle
    void start() override;
    void stop() override;

    void info_json(json &j) const override;
};

class PolicyManager : public AbstractManager<Policy>
{
    mutable std::mutex _load_mutex;

    CoreRegistry *_registry;

public:
    PolicyManager(CoreRegistry *registry)
        : _registry(registry)
    {
    }

    virtual ~PolicyManager()
    {
    }
    void load_from_str(const std::string &str);
    void load(const YAML::Node &tap_yaml);
};

}