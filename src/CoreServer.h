/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "CoreRegistry.h"
#include "HttpServer.h"
#include <chrono>
#include <spdlog/spdlog.h>

namespace visor {

struct PrometheusConfig {
    std::string default_path;
    std::string instance_label;
};

class CoreServer
{

    HttpServer _svr;
    CoreRegistry *_registry;

    std::shared_ptr<spdlog::logger> _logger;
    std::chrono::system_clock::time_point _start_time;

    void _setup_routes(const PrometheusConfig &prom_config);

public:
    CoreServer(CoreRegistry *registry, std::shared_ptr<spdlog::logger> logger, const HttpConfig &http_config, const PrometheusConfig &prom_config);
    ~CoreServer();

    void start(const std::string &host, int port);
    void stop();

    const CoreRegistry *registry() const
    {
        return _registry;
    }

    CoreRegistry *registry()
    {
        return _registry;
    }

    void set_http_logger(httplib::Logger logger)
    {
        _svr.set_logger(logger);
    }
};

}