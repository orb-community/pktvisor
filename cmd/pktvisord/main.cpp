#include <csignal>
#include <functional>
#include <iostream>
#include <map>

#include <cpp-httplib/httplib.h>
#include <docopt/docopt.h>

#include "HandlerManager.h"
#include "InputModulePlugin.h"
#include "InputStreamManager.h"

#include <Corrade/PluginManager/Manager.h>
#include <Corrade/PluginManager/PluginMetadata.h>
#include <Corrade/Utility/Arguments.h>
#include <Corrade/Utility/ConfigurationGroup.h>
#include <Corrade/Utility/Debug.h>
#include <Corrade/Utility/DebugStl.h>

#include "config.h" // FIXME
#include "inputs/static_plugins.h"

static const char USAGE[] =
    R"(pktvisord.
    Usage:
      pktvisord [-b BPF] [-l HOST] [-p PORT] [-H HOSTSPEC] [--periods P] [--summary] [--geo-city FILE] [--geo-asn FILE]
                [--max-deep-sample N]
                TARGET
      pktvisord (-h | --help)
      pktvisord --version

    pktvisord summarizes your data streams.

    TARGET is either a network interface, an IP address (4 or 6) or a pcap file (ending in .pcap or .cap)

    Options:
      -l HOST               Run metrics webserver on the given host or IP [default: localhost]
      -p PORT               Run metrics webserver on the given port [default: 10853]
      -b BPF                Filter packets using the given BPF string
      --geo-city FILE       GeoLite2 City database to use for IP to Geo mapping (if enabled)
      --geo-asn FILE        GeoLite2 ASN database to use for IP to ASN mapping (if enabled)
      --max-deep-sample N   Never deep sample more than N% of packets (an int between 0 and 100) [default: 100]
      --periods P           Hold this many 60 second time periods of history in memory [default: 5]
      --summary             Instead of a time window with P periods, summarize all packets into one bucket for entire time period.
                            Useful for executive summary of (and applicable only to) a pcap file. [default: false]
      -H HOSTSPEC           Specify subnets (comma separated) to consider HOST, in CIDR form. In live capture this /may/ be detected automatically
                            from capture device but /must/ be specified for pcaps. Example: "10.0.1.0/24,10.0.2.1/32,2001:db8::/64"
                            Specifying this for live capture will append to any automatic detection.
      -h --help             Show this screen
      --version             Show version
)";

namespace {
std::function<void(int)> shutdown_handler;
void signal_handler(int signal)
{
    shutdown_handler(signal);
}
}

int main(int argc, char *argv[])
{
    int result{0};

    std::map<std::string, docopt::value> args = docopt::docopt(USAGE,
        {argv + 1, argv + argc},
        true,              // show help if requested
        PKTVISOR_VERSION); // version string

    Corrade::PluginManager::Manager<pktvisor::InputModulePlugin> inputRegistry;

    httplib::Server svr;
    svr.set_logger([](const auto &req, const auto &res) {
        Corrade::Utility::Debug{} << req.path << " " << res.status;
    });
    shutdown_handler = [&](int signal) {
        Corrade::Utility::Debug{} << "closing down";
        svr.stop();
        // TODO gracefully close all inputs and handlers
    };
    svr.Get("/api/v1/server/stop", [&](const httplib::Request &req, httplib::Response &res) {
        shutdown_handler(0);
    });
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::shared_ptr<pktvisor::InputStreamManager> input_manager = std::make_shared<pktvisor::InputStreamManager>();
    pktvisor::HandlerManager handler_manager(svr);

    // set up input modules
    // TODO store instances in vector to keep alive
    Corrade::Containers::Pointer<pktvisor::InputModulePlugin> mod;
    for (auto &s : inputRegistry.pluginList()) {
        mod = inputRegistry.instantiate(s);
        mod->init_module(input_manager, svr);
    }

    auto host = args["-l"].asString();
    auto port = args["-p"].asLong();

    try {
        if (!svr.bind_to_port(host.c_str(), port)) {
            throw std::runtime_error("unable to bind host/port");
        }
        std::cerr << "web server listening on " << host << ":" << port << std::endl;
        if (!svr.listen_after_bind()) {
            throw std::runtime_error("unable to listen");
        }
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        result = -1;
    }

    return result;
}
