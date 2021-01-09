#ifndef PKTVISORD_HANDLERMODULEPLUGIN_H
#define PKTVISORD_HANDLERMODULEPLUGIN_H

#include "AbstractPlugin.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include <string>

namespace pktvisor {

class HandlerModulePlugin : public AbstractPlugin
{
protected:
    std::shared_ptr<pktvisor::InputStreamManager> _input_manager;
    std::shared_ptr<pktvisor::HandlerManager> _handler_manager;

    virtual void _setup_routes(HttpServer &svr) = 0;

public:
    static std::string pluginInterface()
    {
        return "com.ns1.module.handler/1.0";
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

    void init_module(std::shared_ptr<pktvisor::InputStreamManager> im,
        std::shared_ptr<pktvisor::HandlerManager> hm,
        HttpServer &svr);
};

}

#endif //PKTVISORD_HANDLERMODULEPLUGIN_H
