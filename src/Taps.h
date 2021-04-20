/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractManager.h"
#include "AbstractModule.h"
#include "Configurable.h"
#include "InputStreamManager.h"
#include <yaml-cpp/yaml.h>

namespace visor {

class Tap : public AbstractModule
{

public:
    Tap(const std::string &name)
        : AbstractModule(name)
    {
    }
};

class TapManager : public AbstractManager<Tap>
{

    const InputStreamManager *_input_manager;

public:
    TapManager(const InputStreamManager *inputManager)
        : _input_manager(inputManager)
    {
    }

    virtual ~TapManager()
    {
    }

    void load(const YAML::Node &tap_yaml);
};

}