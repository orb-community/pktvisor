/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "CoreServer.h"
#include "HandlerManager.h"
#include "Metrics.h"
#include "visor_config.h"
#include <chrono>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <spdlog/stopwatch.h>
#include <vector>

namespace visor {

CoreServer::CoreServer(bool read_only, const PrometheusConfig &prom_config)
    : _svr(read_only)
    , _mgrs(&_svr)
    , _start_time(std::chrono::system_clock::now())
{

    _logger = spdlog::get("visor");
    if (!_logger) {
        _logger = spdlog::stderr_color_mt("visor");
    }

    _setup_routes(prom_config);

    if (!prom_config.instance.empty()) {
        Metric::add_base_label("instance", prom_config.instance);
    }
}

void CoreServer::start(const std::string &host, int port)
{
    if (!_svr.bind_to_port(host.c_str(), port)) {
        throw std::runtime_error("unable to bind host/port");
    }
    _logger->info("web server listening on {}:{}", host, port);
    if (!_svr.listen_after_bind()) {
        throw std::runtime_error("error during listen");
    }
}

void CoreServer::stop()
{
    _svr.stop();
}

CoreServer::~CoreServer()
{
    stop();
}

void CoreServer::_setup_routes(const PrometheusConfig &prom_config)
{

    _logger->info("Initialize server control plane");

    // Stop the server
    _svr.Delete(
        "/api/v1/server", [&]([[maybe_unused]] const httplib::Request &req, [[maybe_unused]] httplib::Response &res) {
            stop();
        });

    // General metrics retriever
    _svr.Get("/api/v1/metrics/app", [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
        json j;
        try {
            j["app"]["version"] = VISOR_VERSION_NUM;
            j["app"]["up_time_min"] = float(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - _start_time).count()) / 60;
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    // DEPRECATED
    _svr.Get("/api/v1/metrics/rates", [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
        json j;
        try {
            // just backwards compatibility
            j["packets"]["in"] = 0;
            j["packets"]["out"] = 0;
            j["warning"] = "deprecated: use 'live' data from /api/v1/metrics/bucket/0 instead";
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Get(R"(/api/v1/metrics/bucket/(\d+))", [&](const httplib::Request &req, httplib::Response &res) {
        json j;
        bool bc_period{false};
        try {
            uint64_t period(std::stol(req.matches[1]));
            auto [handler_modules, hm_lock] = _mgrs.handler_manager()->module_get_all_locked();
            for (auto &[name, mod] : handler_modules) {
                auto hmod = dynamic_cast<StreamHandler *>(mod.get());
                // TODO need to add policy name, break backwards compatible since multiple otherwise policies will overwrite
                if (hmod) {
                    spdlog::stopwatch sw;
                    hmod->window_json(j, period, false);
                    // hoist up the first "period" we see for backwards compatibility with 3.0.x
                    if (!bc_period && j["1m"][hmod->schema_key()].contains("period")) {
                        j["1m"]["period"] = j["1m"][hmod->schema_key()]["period"];
                        bc_period = true;
                    }
                    _logger->debug("{} elapsed time: {}", hmod->name(), sw);
                }
            }
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Get(R"(/api/v1/metrics/window/(\d+))", [&](const httplib::Request &req, httplib::Response &res) {
        json j;
        try {
            uint64_t period(std::stol(req.matches[1]));
            auto [handler_modules, hm_lock] = _mgrs.handler_manager()->module_get_all_locked();
            for (auto &[name, mod] : handler_modules) {
                auto hmod = dynamic_cast<StreamHandler *>(mod.get());
                // TODO need to add policy name, break backwards compatible since multiple otherwise policies will overwrite
                if (hmod) {
                    spdlog::stopwatch sw;
                    hmod->window_json(j, period, true);
                    _logger->debug("{} elapsed time: {}", hmod->name(), sw);
                }
            }
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });
    _svr.Get(R"(/api/v1/taps)", [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
        json j;
        try {
            auto [handler_modules, hm_lock] = _mgrs.tap_manager()->module_get_all_locked();
            for (auto &[name, mod] : handler_modules) {
                auto tmod = dynamic_cast<Tap *>(mod.get());
                if (tmod) {
                    tmod->info_json(j[tmod->name()]);
                }
            }
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });
    if (!prom_config.path.empty()) {
        _logger->info("enabling prometheus metrics on: {}", prom_config.path);
        _svr.Get(prom_config.path.c_str(), [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
            std::stringstream output;
            try {
                auto [handler_modules, hm_lock] = _mgrs.handler_manager()->module_get_all_locked();
                for (auto &[name, mod] : handler_modules) {
                    auto hmod = dynamic_cast<StreamHandler *>(mod.get());
                    if (hmod) {
                        spdlog::stopwatch sw;
                        hmod->window_prometheus(output);
                        _logger->debug("{} elapsed time: {}", hmod->name(), sw);
                    }
                }
                res.set_content(output.str(), "text/plain");
            } catch (const std::exception &e) {
                res.status = 500;
                res.set_content(e.what(), "text/plain");
            }
        });
    }
}

}