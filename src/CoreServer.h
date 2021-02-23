#pragma once

#include "HandlerManager.h"
#include "HandlerModulePlugin.h"
#include "HttpServer.h"
#include "InputModulePlugin.h"
#include "InputStreamManager.h"
#include <Corrade/PluginManager/Manager.h>
#include <Corrade/PluginManager/PluginMetadata.h>
#include <atomic>
#include <spdlog/spdlog.h>

namespace vizer {

class CoreServer
{
public:
private:
    typedef Corrade::PluginManager::Manager<InputModulePlugin> InputPluginRegistry;
    typedef Corrade::PluginManager::Manager<HandlerModulePlugin> HandlerPluginRegistry;
    typedef Corrade::Containers::Pointer<InputModulePlugin> InputPluginPtr;
    typedef Corrade::Containers::Pointer<HandlerModulePlugin> HandlerPluginPtr;

    InputPluginRegistry _input_registry;
    std::vector<InputPluginPtr> _input_plugins;

    HandlerPluginRegistry _handler_registry;
    std::vector<HandlerPluginPtr> _handler_plugins;

    vizer::HttpServer _svr;

    std::unique_ptr<InputStreamManager> _input_manager;
    std::unique_ptr<HandlerManager> _handler_manager;

    std::shared_ptr<spdlog::logger> _logger;

    void _setup_routes();

public:
    CoreServer(bool read_only, std::shared_ptr<spdlog::logger> logger);
    ~CoreServer();

    void start(const std::string &host, int port);
    void stop();

    void set_http_logger(httplib::Logger logger)
    {
        _svr.set_logger(logger);
    }

    InputStreamManager *input_manager()
    {
        return _input_manager.get();
    }
    HandlerManager *handler_manager()
    {
        return _handler_manager.get();
    }
};

}