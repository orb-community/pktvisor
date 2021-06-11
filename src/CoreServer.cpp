/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "CoreServer.h"
#include "HandlerManager.h"
#include "Metrics.h"
#include "Policies.h"
#include "Taps.h"
#include "visor_config.h"
#include <chrono>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <spdlog/stopwatch.h>
#include <vector>

namespace visor {

visor::CoreServer::CoreServer(std::shared_ptr<spdlog::logger> logger, const HttpConfig &http_config, const PrometheusConfig &prom_config)
    : _svr(http_config)
    , _registry(&_svr)
    , _logger(logger)
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
        throw std::runtime_error("unable to bind to " + host + ":" + std::to_string(port));
    }
    _logger->info("web server listening on {}:{}", host, port);
    if (!_svr.listen_after_bind()) {
        throw std::runtime_error("error during listen");
    }
}

void CoreServer::stop()
{
    _svr.stop();
    _registry.stop();
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
    // rates, DEPRECATED
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
    // 3.0.x compatible: reference "default" policy
    _svr.Get(R"(/api/v1/metrics/bucket/(\d+))", [&](const httplib::Request &req, httplib::Response &res) {
        json j;
        bool bc_period{false};
        if (!_registry.policy_manager()->module_exists("default")) {
            res.status = 404;
            j["error"] = "no \"default\" policy exists";
            res.set_content(j.dump(), "text/json");
            return;
        }
        auto [policy, lock] = _registry.policy_manager()->module_get_locked("default");
        try {
            uint64_t period(std::stol(req.matches[1]));
            for (auto &mod : policy->modules()) {
                auto hmod = dynamic_cast<StreamHandler *>(mod);
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
    // 3.0.x compatible: reference "default" policy
    _svr.Get(R"(/api/v1/metrics/window/(\d+))", [&](const httplib::Request &req, httplib::Response &res) {
        json j;
        if (!_registry.policy_manager()->module_exists("default")) {
            res.status = 404;
            j["error"] = "no \"default\" policy exists";
            res.set_content(j.dump(), "text/json");
            return;
        }
        auto [policy, lock] = _registry.policy_manager()->module_get_locked("default");
        try {
            uint64_t period(std::stol(req.matches[1]));
            for (auto &mod : policy->modules()) {
                auto hmod = dynamic_cast<StreamHandler *>(mod);
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
    // "default" policy prometheus
    if (!prom_config.path.empty()) {
        _logger->info("enabling prometheus metrics for \"default\" policy on: {}", prom_config.path);
        _svr.Get(prom_config.path.c_str(), [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
            std::stringstream output;
            if (!_registry.policy_manager()->module_exists("default")) {
                res.status = 404;
                return;
            }
            auto [policy, lock] = _registry.policy_manager()->module_get_locked("default");
            try {
                for (auto &mod : policy->modules()) {
                    auto hmod = dynamic_cast<StreamHandler *>(mod);
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
    // Taps
    _svr.Get(R"(/api/v1/taps)", [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
        json j;
        try {
            auto [tap_modules, hm_lock] = _registry.tap_manager()->module_get_all_locked();
            for (auto &[name, mod] : tap_modules) {
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
    // Policies
    _svr.Get(R"(/api/v1/policies)", [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
        json j;
        try {
            auto [policy_modules, hm_lock] = _registry.policy_manager()->module_get_all_locked();
            for (auto &[name, mod] : policy_modules) {
                auto tmod = dynamic_cast<Policy *>(mod.get());
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
    _svr.Get(R"(/api/v1/policies/(\w+))", [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
        json j;
        auto name = req.matches[1];
        if (!_registry.policy_manager()->module_exists(name)) {
            res.status = 404;
            j["error"] = "policy does not exists";
            res.set_content(j.dump(), "text/json");
            return;
        }
        try {
            auto [policy, lock] = _registry.policy_manager()->module_get_locked("default");
            policy->info_json(j);
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });
}

}