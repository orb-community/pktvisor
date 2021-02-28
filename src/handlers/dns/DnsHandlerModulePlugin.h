/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "HandlerModulePlugin.h"

namespace vizer::handler::dns {

class DnsHandlerModulePlugin : public HandlerModulePlugin
{

protected:
    void _setup_routes(HttpServer &svr) override;

public:
    explicit DnsHandlerModulePlugin(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : vizer::HandlerModulePlugin{manager, plugin}
    {
    }

    std::string name() const override
    {
        return "DnsHandler";
    }
};
}

