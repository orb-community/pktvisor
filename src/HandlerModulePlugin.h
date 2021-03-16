/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractPlugin.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include <string>

namespace visor {

class HandlerModulePlugin : public AbstractPlugin
{
protected:
    visor::InputStreamManager *_input_manager;
    visor::HandlerManager *_handler_manager;

    virtual void _setup_routes(HttpServer &svr) = 0;

public:
    static std::string pluginInterface()
    {
        return "dev.visor.module.handler/1.0";
    }

    static std::vector<std::string> pluginSearchPaths()
    {
        return {""};
    }

    explicit HandlerModulePlugin(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : AbstractPlugin{manager, plugin}
    {
    }

    virtual std::string name() const = 0;

    void init_module(InputStreamManager *im,
        HandlerManager *hm,
        HttpServer &svr);

    void init_module(InputStreamManager *im,
        HandlerManager *hm);
};

}

