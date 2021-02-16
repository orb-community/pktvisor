#pragma once

#include "AbstractPlugin.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include <string>

namespace vizer {

class HandlerModulePlugin : public AbstractPlugin
{
protected:
    vizer::InputStreamManager *_input_manager;
    vizer::HandlerManager *_handler_manager;

    virtual void _setup_routes(HttpServer &svr) = 0;

public:
    static std::string pluginInterface()
    {
        return "dev.vizer.module.handler/1.0";
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

    void init_module(InputStreamManager *im,
        HandlerManager *hm,
        HttpServer &svr);

    void init_module(InputStreamManager *im,
        HandlerManager *hm);
};

}

