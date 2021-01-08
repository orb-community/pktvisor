#include "NetHandlerModulePlugin.h"
#include "NetStreamHandler.h"
#include <Corrade/PluginManager/AbstractManager.h>

CORRADE_PLUGIN_REGISTER(NetHandler, pktvisor::handler::NetHandlerModulePlugin,
    "com.ns1.module.handler/1.0")

namespace pktvisor {
namespace handler {

void NetHandlerModulePlugin::_setup_routes(HttpServer &svr)
{
}

}
}