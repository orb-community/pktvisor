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

    if (!prom_config.instance_label.empty()) {
        Metric::add_static_label("instance", prom_config.instance_label);
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
        try {
            auto [policy, lock] = _registry.policy_manager()->module_get_locked("default");
            uint64_t period(std::stol(req.matches[1]));
            for (auto &mod : policy->modules()) {
                auto hmod = dynamic_cast<StreamHandler *>(mod);
                if (hmod) {
                    spdlog::stopwatch sw;
                    hmod->window_json(j["1m"], period, false);
                    // hoist up the first "period" we see for backwards compatibility with 3.0.x
                    if (!bc_period && j["1m"][hmod->schema_key()].contains("period")) {
                        j["1m"]["period"] = j["1m"][hmod->schema_key()]["period"];
                        bc_period = true;
                    }
                    _logger->debug("{} bucket window_json elapsed time: {}", hmod->name(), sw);
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
        try {
            auto [policy, lock] = _registry.policy_manager()->module_get_locked("default");
            uint64_t period(std::stol(req.matches[1]));
            for (auto &mod : policy->modules()) {
                auto hmod = dynamic_cast<StreamHandler *>(mod);
                if (hmod) {
                    spdlog::stopwatch sw;
                    auto key = fmt::format("{}m", period);
                    hmod->window_json(j[key], period, true);
                    _logger->debug("{} window_json {} elapsed time: {}", hmod->name(), period, sw);
                }
            }
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    // "default" policy prometheus
    if (!prom_config.default_path.empty()) {
        _logger->info("enabling prometheus metrics for \"default\" policy on: {}", prom_config.default_path);
        _svr.Get(prom_config.default_path.c_str(), [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
            if (!_registry.policy_manager()->module_exists("default")) {
                res.status = 404;
                return;
            }
            try {
                std::stringstream output;
                auto [policy, lock] = _registry.policy_manager()->module_get_locked("default");
                for (auto &mod : policy->modules()) {
                    auto hmod = dynamic_cast<StreamHandler *>(mod);
                    if (hmod) {
                        spdlog::stopwatch sw;
                        hmod->window_prometheus(output, {{"policy", "default"}});
                        _logger->debug("{} window_prometheus elapsed time: {}", hmod->name(), sw);
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
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    // Policies
    _svr.Get(R"(/api/v1/policies)", [&]([[maybe_unused]] const httplib::Request &req, httplib::Response &res) {
        json j = json::object();
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
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Post(R"(/api/v1/policies)", [&](const httplib::Request &req, httplib::Response &res) {
        json j = json::object();
        if (!req.has_header("Content-Type")) {
            res.status = 400;
            j["error"] = "must include Content-Type header";
            res.set_content(j.dump(), "text/json");
            return;
        }
        auto content_type = req.get_header_value("Content-Type");
        if (content_type != "application/x-yaml") {
            res.status = 400;
            j["error"] = "Content-Type not supported";
            res.set_content(j.dump(), "text/json");
            return;
        }
        try {
            auto policies = _registry.policy_manager()->load_from_str(req.body);
            for (auto &mod : policies) {
                mod->info_json(j[mod->name()]);
            }
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Get(fmt::format("/api/v1/policies/({})", AbstractModule::MODULE_ID_REGEX).c_str(), [&](const httplib::Request &req, httplib::Response &res) {
        json j = json::object();
        auto name = req.matches[1];
        if (!_registry.policy_manager()->module_exists(name)) {
            res.status = 404;
            j["error"] = "policy does not exists";
            res.set_content(j.dump(), "text/json");
            return;
        }
        try {
            auto [policy, lock] = _registry.policy_manager()->module_get_locked(name);
            policy->info_json(j[name]);
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Delete(fmt::format("/api/v1/policies/({})", AbstractModule::MODULE_ID_REGEX).c_str(), [&](const httplib::Request &req, httplib::Response &res) {
        json j = json::object();
        auto name = req.matches[1];
        if (!_registry.policy_manager()->module_exists(name)) {
            res.status = 404;
            j["error"] = "policy does not exists";
            res.set_content(j.dump(), "text/json");
            return;
        }
        try {
            auto [policy, lock] = _registry.policy_manager()->module_get_locked(name);
            policy->stop();
            lock.unlock();
            // TODO chance of race here
            _registry.policy_manager()->module_remove(name);
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Get(fmt::format("/api/v1/policies/({})/metrics/(window|bucket)/(\\d+)", AbstractModule::MODULE_ID_REGEX).c_str(), [&](const httplib::Request &req, httplib::Response &res) {
        json j = json::object();
        auto name = req.matches[1];
        std::vector<std::string> plist;
        if (name == "__all") {
            // special route to get all policy metrics in one call, for scraping performance reasons
            plist = _registry.policy_manager()->module_get_keys();
        } else if (!_registry.policy_manager()->module_exists(name)) {
            res.status = 404;
            j["error"] = "policy does not exist";
            res.set_content(j.dump(), "text/json");
            return;
        } else {
            plist.emplace_back(name);
        }
        try {
            for (const auto &p_mname : plist) {
                spdlog::stopwatch psw;
                auto [policy, lock] = _registry.policy_manager()->module_get_locked(p_mname);
                uint64_t period(std::stol(req.matches[3]));
                for (auto &mod : policy->modules()) {
                    auto hmod = dynamic_cast<StreamHandler *>(mod);
                    assert(hmod);
                    try {
                        spdlog::stopwatch hsw;
                        hmod->window_json(j[policy->name()][hmod->name()], period, req.matches[2] == "window");
                        _logger->debug("{} handler bucket json elapsed time: {}", hmod->name(), hsw);
                    } catch (const PeriodException &e) {
                        // if period is bad for a single policy in __all mode, skip it. otherwise fail
                        if (name == "__all") {
                            _logger->warn("{} handler for policy {} had a PeriodException, skipping: {}", hmod->name(), policy->name(), e.what());
                            j.erase(policy->name());
                            continue;
                        } else {
                            throw e;
                        }
                    }
                }
                _logger->debug("{} policy json metrics elapsed time: {}", policy->name(), psw);
            }
            res.set_content(j.dump(), "text/json");
        } catch (const PeriodException &e) {
            res.status = 425; // 425 Too Early
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            j["error"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Get(fmt::format("/api/v1/policies/({})/metrics/prometheus", AbstractModule::MODULE_ID_REGEX).c_str(), [&](const httplib::Request &req, httplib::Response &res) {
        auto name = req.matches[1];
        if (!_registry.policy_manager()->module_exists(name)) {
            res.status = 404;
            res.set_content("policy does not exists", "text/plain");
            return;
        }
        try {
            std::stringstream output;
            auto [policy, lock] = _registry.policy_manager()->module_get_locked(name);
            for (auto &mod : policy->modules()) {
                auto hmod = dynamic_cast<StreamHandler *>(mod);
                if (hmod) {
                    spdlog::stopwatch sw;
                    hmod->window_prometheus(output, {{"policy", name}, {"module", hmod->name()}});
                    _logger->debug("{} window_prometheus elapsed time: {}", hmod->name(), sw);
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