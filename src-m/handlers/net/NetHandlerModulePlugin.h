#ifndef PKTVISORD_NETHANDLERMODULEPLUGIN_H
#define PKTVISORD_NETHANDLERMODULEPLUGIN_H

#include "HandlerModulePlugin.h"
#include "NetStreamHandler.h"
#include "PcapInputStream.h"

namespace pktvisor {
namespace handler {
class NetHandlerModulePlugin : public HandlerModulePlugin
{
protected:
    void _setup_routes(HttpServer &svr) override;

public:
    explicit NetHandlerModulePlugin(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : pktvisor::HandlerModulePlugin{manager, plugin}
    {
    }

    std::string name() const override
    {
        return "NetHandlerModulePlugin";
    }

    const NetStreamHandler *op_create(std::shared_ptr<pktvisor::input::PcapInputStream> stream, const std::string &name);
};
}
}

#endif //PKTVISORD_NETHANDLERMODULEPLUGIN_H
