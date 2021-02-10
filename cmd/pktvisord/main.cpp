#include <csignal>
#include <functional>
#include <map>
#include <vector>

#include "HttpServer.h"
#include <docopt/docopt.h>

#include "HandlerManager.h"
#include "HandlerModulePlugin.h"
#include "InputModulePlugin.h"
#include "InputStreamManager.h"
#include <Corrade/PluginManager/Manager.h>
#include <Corrade/PluginManager/PluginMetadata.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include "config.h" // FIXME
#include "handlers/static_plugins.h"
#include "inputs/static_plugins.h"

static const char USAGE[] =
    R"(pktvisord.
    Usage:
      pktvisord [-l HOST] [-p PORT] [--full-api] [--geo-city FILE] [--geo-asn FILE]
                [--periods P] [--max-deep-sample N]
      pktvisord [-l HOST] [-p PORT] [--full-api] [--geo-city FILE] [--geo-asn FILE]
                [--periods P] [--max-deep-sample N]
                [-b BPF] [-H HOSTSPEC] [PCAP_TARGET]
      pktvisord (-h | --help)
      pktvisord --version

    pktvisord summarizes your data streams and exposes a REST API control plane.

    Base Options:
      -l HOST               Run webserver on the given host or IP [default: localhost]
      -p PORT               Run webserver on the given port [default: 10853]
      --full-api            Enable full REST API giving complete control plane functionality [default: false]
                            When false, the exposed API is read-only access to summarized metrics.
                            When true, write access is enabled for all modules.

      -h --help             Show this screen
      --version             Show version

      --geo-city FILE       GeoLite2 City database to use for IP to Geo mapping (if enabled)
      --geo-asn FILE        GeoLite2 ASN database to use for IP to ASN mapping (if enabled)

    Handler Module Defaults

      --max-deep-sample N   Never deep sample more than N% of streams (an int between 0 and 100) [default: 100]
      --periods P           Hold this many 60 second time periods of history in memory [default: 5]

    pcap Input Module

      PCAP_TARGET, if specified, is either a network interface or an IP address (4 or 6)

      -b BPF                Filter packets using the given BPF string
      -H HOSTSPEC           Specify subnets (comma separated) to consider HOST, in CIDR form. In live capture this /may/ be detected automatically
                            from capture device but /must/ be specified for pcaps. Example: "10.0.1.0/24,10.0.2.1/32,2001:db8::/64"
                            Specifying this for live capture will append to any automatic detection.

)";

namespace {
std::function<void(int)> shutdown_handler;
void signal_handler(int signal)
{
    shutdown_handler(signal);
}
}

typedef Corrade::PluginManager::Manager<vizer::InputModulePlugin> InputPluginRegistry;
typedef Corrade::PluginManager::Manager<vizer::HandlerModulePlugin> HandlerPluginRegistry;
typedef Corrade::Containers::Pointer<vizer::InputModulePlugin> InputPluginPtr;
typedef Corrade::Containers::Pointer<vizer::HandlerModulePlugin> HandlerPluginPtr;

int main(int argc, char *argv[])
{
    int result{0};

    auto console = spdlog::stdout_color_mt("console");
    auto err_logger = spdlog::stderr_color_mt("stderr");

    std::map<std::string, docopt::value> args = docopt::docopt(USAGE,
        {argv + 1, argv + argc},
        true,           // show help if requested
        VIZER_VERSION); // version string

    vizer::HttpServer svr(!args["--full-api"].asBool());
    svr.set_logger([&err_logger](const auto &req, const auto &res) {
        err_logger->info("REQUEST: {} {} {}", req.method, req.path, res.status);
    });

    // inputs
    InputPluginRegistry inputRegistry;
    auto inputManager = std::make_unique<vizer::InputStreamManager>();
    std::vector<InputPluginPtr> inputPlugins;

    // initialize input plugins
    for (auto &s : inputRegistry.pluginList()) {
        InputPluginPtr mod = inputRegistry.instantiate(s);
        console->info("Load input plugin: {} {}", mod->name(), mod->pluginInterface());
        mod->init_module(inputManager.get(), svr);
        inputPlugins.emplace_back(std::move(mod));
    }

    // handlers
    HandlerPluginRegistry handlerRegistry;
    auto handlerManager = std::make_unique<vizer::HandlerManager>();
    std::vector<HandlerPluginPtr> handlerPlugins;

    // initialize handler plugins
    for (auto &s : handlerRegistry.pluginList()) {
        HandlerPluginPtr mod = handlerRegistry.instantiate(s);
        console->info("Load handler plugin: {} {}", mod->name(), mod->pluginInterface());
        mod->init_module(inputManager.get(), handlerManager.get(), svr);
        handlerPlugins.emplace_back(std::move(mod));
    }

    shutdown_handler = [&](int signal) {
        console->info("Shutting down");
        svr.stop();
        // gracefully close all inputs and handlers
        auto [input_modules, im_lock] = inputManager->module_get_all_locked();
        for (auto &[name, mod] : input_modules) {
            console->info("Stopping input instance: {}", mod->name());
            mod->stop();
        }
        auto [handler_modules, hm_lock] = handlerManager->module_get_all_locked();
        for (auto &[name, mod] : handler_modules) {
            console->info("Stopping handler instance: {}", mod->name());
            mod->stop();
        }
    };

    console->info("Initialize server control plane");
    svr.Get("/api/v1/server/stop", [&](const httplib::Request &req, httplib::Response &res) {
        shutdown_handler(SIGUSR1);
    });
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    auto host = args["-l"].asString();
    auto port = args["-p"].asLong();

    try {
        if (!svr.bind_to_port(host.c_str(), port)) {
            throw std::runtime_error("unable to bind host/port");
        }
        console->info("web server listening on {}:{}", host, port);
        if (!svr.listen_after_bind()) {
            throw std::runtime_error("error during listen");
        }
    } catch (const std::exception &e) {
        err_logger->error("Fatal error: {}", e.what());
        result = -1;
    }

    return result;
}
