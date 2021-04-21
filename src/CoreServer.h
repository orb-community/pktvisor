/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "CoreManagers.h"
#include "HttpServer.h"
#include <chrono>
#include <spdlog/spdlog.h>

namespace visor {

struct PrometheusConfig {
    std::string path;
    std::string instance;
};

class CoreServer
{

    HttpServer _svr;
    CoreManagers _mgrs;

    std::shared_ptr<spdlog::logger> _logger;
    std::chrono::system_clock::time_point _start_time;

    void _setup_routes(const PrometheusConfig &prom_config);

public:
    CoreServer(bool read_only, const PrometheusConfig &prom_config);
    ~CoreServer();

    void start(const std::string &host, int port);
    void stop();

    const CoreManagers *mgrs() const
    {
        return &_mgrs;
    }

    CoreManagers *mgrs()
    {
        return &_mgrs;
    }

    void set_http_logger(httplib::Logger logger)
    {
        _svr.set_logger(logger);
    }
};

}