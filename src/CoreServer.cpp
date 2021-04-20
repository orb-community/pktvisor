/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "CoreServer.h"
#include "Metrics.h"
#include "visor_config.h"
#include <chrono>
#include <spdlog/stopwatch.h>
#include <vector>

visor::CoreServer::CoreServer(bool read_only, std::shared_ptr<spdlog::logger> logger, const PrometheusConfig &prom_config)
    : _svr(read_only)
    , _logger(logger)
    , _start_time(std::chrono::system_clock::now())
{

    // inputs
    _input_manager = std::make_unique<InputStreamManager>();

    // initialize input plugins
    for (auto &s : _input_registry.pluginList()) {
        InputPluginPtr mod = _input_registry.instantiate(s);
        _logger->info("Load input plugin: {} {}", mod->name(), mod->pluginInterface());
        mod->init_module(_input_manager.get(), _svr);
        _input_plugins.emplace_back(std::move(mod));
    }

    // handlers
    _handler_manager = std::make_unique<HandlerManager>();

    // initialize handler plugins
    for (auto &s : _handler_registry.pluginList()) {
        HandlerPluginPtr mod = _handler_registry.instantiate(s);
        _logger->info("Load handler plugin: {} {}", mod->name(), mod->pluginInterface());
        mod->init_module(_input_manager.get(), _handler_manager.get(), _svr);
        _handler_plugins.emplace_back(std::move(mod));
    }

    _setup_routes(prom_config);
    if (!prom_config.instance.empty()) {
        Metric::add_base_label("instance", prom_config.instance);
    }
}
void visor::CoreServer::start(const std::string &host, int port)
{
    if (!_svr.bind_to_port(host.c_str(), port)) {
        throw std::runtime_error("unable to bind host/port");
    }
    _logger->info("web server listening on {}:{}", host, port);
    if (!_svr.listen_after_bind()) {
        throw std::runtime_error("error during listen");
    }
}
void visor::CoreServer::stop()
{
    _svr.stop();

    // gracefully close all inputs and handlers
    auto [input_modules, im_lock] = _input_manager->module_get_all_locked();
    for (auto &[name, mod] : input_modules) {
        if (mod->running()) {
            _logger->info("Stopping input instance: {}", mod->name());
            mod->stop();
        }
    }
    auto [handler_modules, hm_lock] = _handler_manager->module_get_all_locked();
    for (auto &[name, mod] : handler_modules) {
        if (mod->running()) {
            _logger->info("Stopping handler instance: {}", mod->name());
            mod->stop();
        }
    }
}
visor::CoreServer::~CoreServer()
{
    stop();
}
void visor::CoreServer::_setup_routes(const PrometheusConfig &prom_config)
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
            auto [handler_modules, hm_lock] = _handler_manager->module_get_all_locked();
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
            auto [handler_modules, hm_lock] = _handler_manager->module_get_all_locked();
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
    if (!prom_config.path.empty()) {
        _logger->info("enabling prometheus metrics on: {}", prom_config.path);
        _svr.Get(prom_config.path.c_str(), [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
            std::stringstream output;
            try {
                auto [handler_modules, hm_lock] = _handler_manager->module_get_all_locked();
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
void visor::CoreServer::configure_from_file(const std::string &filename)
{
    YAML::Node config_file = YAML::LoadFile(filename);

    if (!config_file.IsMap() || !config_file["visor"]) {
        throw std::runtime_error("invalid schema");
    }
    if (!config_file["version"] || !config_file["version"].IsScalar() || config_file["version"].as<std::string>() != "1.0") {
        throw std::runtime_error("missing or unsupported version");
    }

    // taps
}
