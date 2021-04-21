/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractPlugin.h"
#include <Corrade/PluginManager/Manager.h>
#include <Corrade/PluginManager/PluginMetadata.h>
#include <string>

namespace visor {

class HandlerModulePlugin : public AbstractPlugin
{

public:
    static std::string pluginInterface()
    {
        return "visor.module.handler/1.0";
    }

    static std::vector<std::string> pluginSearchPaths()
    {
        return {""};
    }

    explicit HandlerModulePlugin(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : AbstractPlugin{manager, plugin}
    {
    }

};

typedef Corrade::PluginManager::Manager<HandlerModulePlugin> HandlerPluginRegistry;
typedef Corrade::Containers::Pointer<HandlerModulePlugin> HandlerPluginPtr;

}
