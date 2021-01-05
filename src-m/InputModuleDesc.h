#ifndef PKTVISORD_INPUTMODULEDESC_H
#define PKTVISORD_INPUTMODULEDESC_H

#include <Corrade/PluginManager/AbstractPlugin.h>
#include <cpp-httplib/httplib.h>
#include <string>
#include <vector>

namespace pktvisor {

class InputModuleDesc : public Corrade::PluginManager::AbstractPlugin
{

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

    virtual void setup_routes(httplib::Server &svr) = 0;
};

}

#endif //PKTVISORD_INPUTMODULEDESC_H
