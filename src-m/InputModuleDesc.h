#ifndef PKTVISORD_INPUTMODULEDESC_H
#define PKTVISORD_INPUTMODULEDESC_H

#include "InputManager.h"
#include <Corrade/PluginManager/AbstractPlugin.h>
#include <cpp-httplib/httplib.h>
#include <string>
#include <vector>

namespace pktvisor {

class InputModuleDesc : public Corrade::PluginManager::AbstractPlugin
{

protected:
    std::shared_ptr<pktvisor::InputManager> _input_manager;

    virtual void _setup_routes(httplib::Server &svr) = 0;

public:
    static std::string pluginInterface()
    {
        return "com.ns1.module.input/1.0";
    }

    static std::vector<std::string> pluginSearchPaths()
    {
        return {""};
    }

    explicit InputModuleDesc(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : AbstractPlugin{manager, plugin}
    {
    }

    virtual std::string name() const = 0;

    void init_module(std::shared_ptr<pktvisor::InputManager> im, httplib::Server &svr);
};

}

#endif //PKTVISORD_INPUTMODULEDESC_H
