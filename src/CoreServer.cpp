#include "CoreServer.h"
#include "vizer_config.h"
#include <chrono>
#include <spdlog/stopwatch.h>
#include <vector>

vizer::CoreServer::CoreServer(bool read_only, std::shared_ptr<spdlog::logger> logger)
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

    _setup_routes();
}
void vizer::CoreServer::start(const std::string &host, int port)
{
    if (!_svr.bind_to_port(host.c_str(), port)) {
        throw std::runtime_error("unable to bind host/port");
    }
    _logger->info("web server listening on {}:{}", host, port);
    if (!_svr.listen_after_bind()) {
        throw std::runtime_error("error during listen");
    }
}
void vizer::CoreServer::stop()
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
vizer::CoreServer::~CoreServer()
{
    stop();
}
void vizer::CoreServer::_setup_routes()
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
            j["app"]["version"] = VIZER_VERSION_NUM;
            j["app"]["up_time_min"] = float(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - _start_time).count()) / 60;
            res.set_content(j.dump(), "text/json");
        } catch (const std::runtime_error &e) {
            res.status = 500;
            j["result"] = e.what();
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
            j["warning"] = "deprecated: use data from /api/v1/metrics/bucket/0 instead";
            res.set_content(j.dump(), "text/json");
        } catch (const std::runtime_error &e) {
            res.status = 500;
            j["result"] = e.what();
            res.set_content(j.dump(), "text/json");
        }
    });
    _svr.Get(R"(/api/v1/metrics/bucket/(\d+))", [&](const httplib::Request &req, httplib::Response &res) {
        json j;
        try {
            uint64_t period(std::stol(req.matches[1]));
            auto [handler_modules, hm_lock] = _handler_manager->module_get_all_locked();
            for (auto &[name, mod] : handler_modules) {
                auto hmod = dynamic_cast<StreamHandler *>(mod.get());
                // TODO need to add policy name, break backwards compatible
                if (hmod) {
                    spdlog::stopwatch sw;
                    hmod->window_json(j, period, false);
                    _logger->debug("{} elapsed time: {}", hmod->name(), sw);
                }
            }
            res.set_content(j.dump(), "text/json");
        } catch (const std::runtime_error &e) {
            res.status = 500;
            j["result"] = e.what();
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
                // TODO need to add policy name, break backwards compatible
                if (hmod) {
                    spdlog::stopwatch sw;
                    hmod->window_json(j, period, true);
                    _logger->debug("{} elapsed time: {}", hmod->name(), sw);
                }
            }
            res.set_content(j.dump(), "text/json");
        } catch (const std::runtime_error &e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });
}
