#ifndef PKTVISORD_DNSHANDLERMODULEPLUGIN_H
#define PKTVISORD_DNSHANDLERMODULEPLUGIN_H

#include "HandlerModulePlugin.h"

namespace pktvisor {
namespace handler {

class DnsHandlerModulePlugin : public HandlerModulePlugin
{

protected:
    void _setup_routes(HttpServer &svr) override;

public:
    explicit DnsHandlerModulePlugin(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : pktvisor::HandlerModulePlugin{manager, plugin}
    {
    }

    std::string name() const override
    {
        return "DnsHandler";
    }
};
}
}

#endif //PKTVISORD_DNSHANDLERMODULEPLUGIN_H
