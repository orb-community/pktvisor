/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractPlugin.h"
#include "InputStreamManager.h"
#include <string>

namespace visor {

class InputModulePlugin : public AbstractPlugin
{

protected:
    InputStreamManager *_input_manager;

    virtual void _setup_routes(HttpServer &svr) = 0;

public:
    static std::string pluginInterface()
    {
        return "visor.module.input/1.0";
    }

    static std::vector<std::string> pluginSearchPaths()
    {
        return {""};
    }

    explicit InputModulePlugin(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : AbstractPlugin{manager, plugin}
    {
    }

    virtual std::string name() const = 0;

    void init_module(InputStreamManager *im, HttpServer &svr);
    void init_module(InputStreamManager *im);
};

}

