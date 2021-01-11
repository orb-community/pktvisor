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
#include <Corrade/Utility/Arguments.h>
#include <Corrade/Utility/ConfigurationGroup.h>
#include <Corrade/Utility/Debug.h>
#include <Corrade/Utility/DebugStl.h>
#include <Corrade/Utility/Format.h>

#include "config.h" // FIXME
#include "handlers/static_plugins.h"
#include "inputs/static_plugins.h"

static const char USAGE[] =
    R"(pktvisord.
    Usage:
      pktvisord [-b BPF] [-l HOST] [-p PORT] [--full-api] [-H HOSTSPEC] [--periods P] [--summary] [--geo-city FILE] [--geo-asn FILE]
                [--max-deep-sample N] [TARGET]
      pktvisord (-h | --help)
      pktvisord --version

    pktvisord summarizes your data streams.

    TARGET is either a network interface, an IP address (4 or 6) or a pcap file (ending in .pcap or .cap)

    Options:
      -l HOST               Run webserver on the given host or IP [default: localhost]
      -p PORT               Run webserver on the given port [default: 10853]
      --full-api            Enable full REST API giving complete control plane functionality [default: false]
                            When false, the exposed API is read-only access to summarized metrics.
                            When true, write access is enabled for all modules.

      --max-deep-sample N   Never deep sample more than N% of streams (an int between 0 and 100) [default: 100]
      --periods P           Hold this many 60 second time periods of history in memory [default: 5]
      -h --help             Show this screen
      --version             Show version

    pcap Input Module
      -b BPF                Filter packets using the given BPF string
      --geo-city FILE       GeoLite2 City database to use for IP to Geo mapping (if enabled)
      --geo-asn FILE        GeoLite2 ASN database to use for IP to ASN mapping (if enabled)
      -H HOSTSPEC           Specify subnets (comma separated) to consider HOST, in CIDR form. In live capture this /may/ be detected automatically
                            from capture device but /must/ be specified for pcaps. Example: "10.0.1.0/24,10.0.2.1/32,2001:db8::/64"
                            Specifying this for live capture will append to any automatic detection.
      --summary             Instead of a time window with P periods, summarize all packets into one bucket for entire time period.
                            Useful for executive summary of (and applicable only to) a pcap file. [default: false]

)";

namespace {
std::function<void(int)> shutdown_handler;
void signal_handler(int signal)
{
    shutdown_handler(signal);
}
}

typedef Corrade::PluginManager::Manager<pktvisor::InputModulePlugin> InputPluginRegistry;
typedef Corrade::PluginManager::Manager<pktvisor::HandlerModulePlugin> HandlerPluginRegistry;
typedef Corrade::Containers::Pointer<pktvisor::InputModulePlugin> InputPluginPtr;
typedef Corrade::Containers::Pointer<pktvisor::HandlerModulePlugin> HandlerPluginPtr;

int main(int argc, char *argv[])
{
    int result{0};

    std::map<std::string, docopt::value> args = docopt::docopt(USAGE,
        {argv + 1, argv + argc},
        true,              // show help if requested
        PKTVISOR_VERSION); // version string

    pktvisor::HttpServer svr;
    svr.set_logger([](const auto &req, const auto &res) {
        Corrade::Utility::Debug{} << req.path << " " << res.status;
    });

    // inputs
    InputPluginRegistry inputRegistry;
    auto inputManager = std::make_shared<pktvisor::InputStreamManager>();
    std::vector<InputPluginPtr> inputPlugins;

    // initialize input plugins
    for (auto &s : inputRegistry.pluginList()) {
        InputPluginPtr mod = inputRegistry.instantiate(s);
        Corrade::Utility::print("Load input plugin: {}\n", mod->name());
        mod->init_module(inputManager, svr);
        inputPlugins.emplace_back(std::move(mod));
    }

    // handlers
    HandlerPluginRegistry handlerRegistry;
    auto handlerManager = std::make_shared<pktvisor::HandlerManager>();
    std::vector<HandlerPluginPtr> handlerPlugins;

    // initialize handler plugins
    for (auto &s : handlerRegistry.pluginList()) {
        HandlerPluginPtr mod = handlerRegistry.instantiate(s);
        Corrade::Utility::print("Load handler plugin: {}\n", mod->name());
        mod->init_module(inputManager, handlerManager, svr);
        handlerPlugins.emplace_back(std::move(mod));
    }

    shutdown_handler = [&](int signal) {
        Corrade::Utility::print("Shutting down\n");
        svr.stop();
        // gracefully close all inputs and handlers
        for (auto &[name, mod] : inputManager->all_modules()) {
            Corrade::Utility::print("Stopping input instance: {}\n", mod->name());
            mod->stop();
        }
        for (auto &[name, mod] : handlerManager->all_modules()) {
            Corrade::Utility::print("Stopping handler instance: {}\n", mod->name());
            mod->stop();
        }
    };

    // TODO remove verb from url
    Corrade::Utility::print("Initialize server control plane\n");
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
        Corrade::Utility::print("web server listening on {}:{}\n", host, port);
        if (!svr.listen_after_bind()) {
            throw std::runtime_error("unable to listen");
        }
    } catch (const std::exception &e) {
        Corrade::Utility::printError("Fatal error: {}\n", e.what());
        result = -1;
    }

    return result;
}
