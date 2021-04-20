/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "HandlerManager.h"
#include "HandlerModulePlugin.h"
#include "HttpServer.h"
#include "InputModulePlugin.h"
#include "InputStreamManager.h"
#include "Taps.h"
#include <atomic>
#include <map>
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

namespace visor {

struct PrometheusConfig {
    std::string path;
    std::string instance;
};

class CoreServer
{

    // these hold plugin instances: these are the types of modules available for instantiation
    InputPluginRegistry _input_registry;
    std::vector<InputPluginPtr> _input_plugins;

    HandlerPluginRegistry _handler_registry;
    std::vector<HandlerPluginPtr> _handler_plugins;

    visor::HttpServer _svr;

    // these hold instances of active modules
    std::unique_ptr<InputStreamManager> _input_manager;
    std::unique_ptr<HandlerManager> _handler_manager;

    std::unique_ptr<TapManager> _tap_manager;

    std::shared_ptr<spdlog::logger> _logger;
    std::chrono::system_clock::time_point _start_time;

    void _setup_routes(const PrometheusConfig &prom_config);

public:
    CoreServer(bool read_only, const PrometheusConfig &prom_config);
    ~CoreServer();

    void start(const std::string &host, int port);
    void stop();

    void configure_from_file(const std::string &filename);

    void set_http_logger(httplib::Logger logger)
    {
        _svr.set_logger(logger);
    }

    const InputStreamManager *input_manager() const
    {
        return _input_manager.get();
    }
    const HandlerManager *handler_manager() const
    {
        return _handler_manager.get();
    }
    const TapManager *tap_manager() const
    {
        return _tap_manager.get();
    }
    const InputPluginRegistry *input_plugin_registry() const
    {
        return &_input_registry;
    }

    InputStreamManager *input_manager()
    {
        return _input_manager.get();
    }
    HandlerManager *handler_manager()
    {
        return _handler_manager.get();
    }
    TapManager *tap_manager()
    {
        return _tap_manager.get();
    }
};

}