#include "CoreServer.h"
#include <vector>

vizer::CoreServer::CoreServer(bool read_only, std::shared_ptr<spdlog::logger> console, std::shared_ptr<spdlog::logger> err)
    : _svr(read_only)
    , _console(console)
    , _err(err)
{

    // inputs
    _input_manager = std::make_unique<InputStreamManager>();
    std::vector<InputPluginPtr> input_plugins;

    // initialize input plugins
    for (auto &s : _input_registry.pluginList()) {
        InputPluginPtr mod = _input_registry.instantiate(s);
        _console->info("Load input plugin: {} {}", mod->name(), mod->pluginInterface());
        mod->init_module(_input_manager.get(), _svr);
        input_plugins.emplace_back(std::move(mod));
    }

    // handlers
    _handler_manager = std::make_unique<HandlerManager>();
    std::vector<HandlerPluginPtr> handler_plugins;

    // initialize handler plugins
    for (auto &s : _handler_registry.pluginList()) {
        HandlerPluginPtr mod = _handler_registry.instantiate(s);
        _console->info("Load handler plugin: {} {}", mod->name(), mod->pluginInterface());
        mod->init_module(_input_manager.get(), _handler_manager.get(), _svr);
        handler_plugins.emplace_back(std::move(mod));
    }

    _setup_routes();
}
void vizer::CoreServer::start(const std::string &host, int port)
{
    if (!_svr.bind_to_port(host.c_str(), port)) {
        throw std::runtime_error("unable to bind host/port");
    }
    _console->info("web server listening on {}:{}", host, port);
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
            _console->info("Stopping input instance: {}", mod->name());
            mod->stop();
        }
    }
    auto [handler_modules, hm_lock] = _handler_manager->module_get_all_locked();
    for (auto &[name, mod] : handler_modules) {
        if (mod->running()) {
            _console->info("Stopping handler instance: {}", mod->name());
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

    _console->info("Initialize server control plane");
    _svr.Get("/api/v1/server/stop", [&]([[maybe_unused]] const httplib::Request &req, [[maybe_unused]] httplib::Response &res) {
        stop();
    });
}
