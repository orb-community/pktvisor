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

