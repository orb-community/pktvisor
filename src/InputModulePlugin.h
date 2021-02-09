#pragma once

#include "AbstractPlugin.h"
#include "InputStreamManager.h"
#include <string>

namespace vizer {

class InputModulePlugin : public AbstractPlugin
{

protected:
    vizer::InputStreamManager *_input_manager;

    virtual void _setup_routes(HttpServer &svr) = 0;

public:
    static std::string pluginInterface()
    {
        return "dev.vizer.module.input/1.0";
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

    void init_module(InputStreamManager *im, HttpServer &svr);
    void init_module(InputStreamManager *im);
};

}

