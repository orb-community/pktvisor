#ifndef PKTVISORD_NETHANDLERMODULEPLUGIN_H
#define PKTVISORD_NETHANDLERMODULEPLUGIN_H

#include "HandlerModulePlugin.h"
#include "NetStreamHandler.h"
#include "PcapInputStream.h"
#include <shared_mutex>

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

    // CRUD interface, must be thread safe
    void op_create(const std::string &input_name, const std::string &handler_name);
    void op_delete(const std::string &handler_name);
};
}
}

#endif //PKTVISORD_NETHANDLERMODULEPLUGIN_H
