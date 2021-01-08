#ifndef PKTVISORD_INPUTMODULEPLUGIN_H
#define PKTVISORD_INPUTMODULEPLUGIN_H

#include "AbstractPlugin.h"
#include "InputStreamManager.h"
#include <string>

namespace pktvisor {

class InputModulePlugin : public AbstractPlugin
{

protected:
    std::shared_ptr<pktvisor::InputStreamManager> _input_manager;

    virtual void _setup_routes(HttpServer &svr) = 0;

public:
    static std::string pluginInterface()
    {
        return "com.ns1.module.input/1.0";
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

    void init_module(std::shared_ptr<pktvisor::InputStreamManager> im, HttpServer &svr);
};

}

#endif //PKTVISORD_INPUTMODULEPLUGIN_H
