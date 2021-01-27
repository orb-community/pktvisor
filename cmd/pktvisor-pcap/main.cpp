#include <csignal>
#include <functional>
#include <map>
#include <vector>

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
#include <Corrade/Utility/Format.h>

#include "config.h" // FIXME
#include "handlers/static_plugins.h"
#include "inputs/static_plugins.h"

#include "handlers/net/NetStreamHandler.h"
#include "inputs/pcap/PcapInputStream.h"

static const char USAGE[] =
    R"(pktvisor-pcap
    Usage:
      pktvisor-pcap [-b BPF] [-H HOSTSPEC] [--geo-city FILE] [--geo-asn FILE] [--max-deep-sample N] [--summary] PCAP
      pktvisor-pcap (-h | --help)
      pktvisor-pcap --version

    Summarize a pcap file

    Options:
      --max-deep-sample N   Never deep sample more than N% of streams (an int between 0 and 100) [default: 100]
      --periods P           Hold this many 60 second time periods of history in memory [default: 5]
      --summary             Instead of a time window with P periods, summarize all packets into one bucket for entire time period.
                            Useful for executive summary of pcap file. [default: false]
      -h --help             Show this screen
      --version             Show version
      -b BPF                Filter packets using the given BPF string
      --geo-city FILE       GeoLite2 City database to use for IP to Geo mapping (if enabled)
      --geo-asn FILE        GeoLite2 ASN database to use for IP to ASN mapping (if enabled)
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

typedef Corrade::PluginManager::Manager<pktvisor::InputModulePlugin> InputPluginRegistry;
typedef Corrade::PluginManager::Manager<pktvisor::HandlerModulePlugin> HandlerPluginRegistry;
typedef Corrade::Containers::Pointer<pktvisor::InputModulePlugin> InputPluginPtr;
typedef Corrade::Containers::Pointer<pktvisor::HandlerModulePlugin> HandlerPluginPtr;

//void handleGeo(const docopt::value &city, const docopt::value &asn)
//{
//    if (city) {
//        if (!metricsManager->haveGeoCity()) {
//            std::cerr << "warning: --geo-city has no effect, lacking compile-time support" << std::endl;
//        } else {
//            metricsManager->setGeoCityDB(city.asString());
//        }
//    }
//    if (asn) {
//        if (!metricsManager->haveGeoASN()) {
//            std::cerr << "warning: --geo-asn has no effect, lacking compile-time support" << std::endl;
//        } else {
//            metricsManager->setGeoASNDB(asn.asString());
//        }
//    }
//}

int main(int argc, char *argv[])
{
    int result{0};

    std::map<std::string, docopt::value> args = docopt::docopt(USAGE,
        {argv + 1, argv + argc},
        true,              // show help if requested
        PKTVISOR_VERSION); // version string

    // inputs
    InputPluginRegistry inputRegistry;
    auto inputManager = std::make_unique<pktvisor::InputStreamManager>();
    std::vector<InputPluginPtr> inputPlugins;

    // initialize input plugins
    for (auto &s : inputRegistry.pluginList()) {
        InputPluginPtr mod = inputRegistry.instantiate(s);
        Corrade::Utility::print("Load input plugin: {}\n", mod->name());
        mod->init_module(inputManager.get());
        inputPlugins.emplace_back(std::move(mod));
    }

    // handlers
    HandlerPluginRegistry handlerRegistry;
    auto handlerManager = std::make_unique<pktvisor::HandlerManager>();
    std::vector<HandlerPluginPtr> handlerPlugins;

    // initialize handler plugins
    for (auto &s : handlerRegistry.pluginList()) {
        HandlerPluginPtr mod = handlerRegistry.instantiate(s);
        Corrade::Utility::print("Load handler plugin: {}\n", mod->name());
        mod->init_module(inputManager.get(), handlerManager.get());
        handlerPlugins.emplace_back(std::move(mod));
    }

    shutdown_handler = [&](int signal) {
        Corrade::Utility::print("Shutting down\n");
        // gracefully close all inputs and handlers
        auto [input_modules, im_lock] = inputManager->all_modules();
        for (auto &[name, mod] : input_modules) {
            Corrade::Utility::print("Stopping input instance: {}\n", mod->name());
            mod->stop();
        }
        auto [handler_modules, hm_lock] = handlerManager->all_modules();
        for (auto &[name, mod] : handler_modules) {
            Corrade::Utility::print("Stopping handler instance: {}\n", mod->name());
            mod->stop();
        }
    };

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    int sampleRate = 100;
    if (args["--max-deep-sample"]) {
        sampleRate = (int)args["--max-deep-sample"].asLong();
        if (sampleRate != 100) {
            Corrade::Utility::print("Using maximum deep sample rate: {}%\n", sampleRate);
        }
    }

    std::string bpf;
    if (args["-b"]) {
        bpf = args["-b"].asString();
    }

    if (args["-H"]) {
        auto spec = args["-H"].asString();
        try {
            //            pktvisor::parseHostSpec(spec, hostIPv4, hostIPv6);
        } catch (const std::exception &e) {
            std::cerr << e.what() << std::endl;
            return -1;
        }
    }

    long periods{0};
    if (args["--periods"]) {
        periods = args["--periods"].asLong();
    }

    try {
        auto inputStream = std::make_unique<pktvisor::input::pcap::PcapInputStream>("pcap");
        inputStream->config_set("pcap_file", args["PCAP"].asString());
        inputStream->config_set("bpf", args["BPF"].asString());
        inputManager->module_add(std::move(inputStream), false);
        auto handler_module = std::make_unique<pktvisor::handler::NetStreamHandler>("net", inputStream.get(), periods, sampleRate);
        handlerManager->module_add(std::move(handler_module));
        inputStream->start();
        //        handleGeo(args["--geo-city"], args["--geo-asn"]);
        //        openPcap(args["TARGET"].asString(), tcpDnsReassembly, bpf);
        //        if (args["--summary"].asBool()) {
        //            // in summary mode we output a single summary of stats
        //            std::cout << std::endl
        //                      << metricsManager->getMetrics() << std::endl;
        //        } else {
        //            // otherwise, merge the max time window available
        //            std::cout << std::endl
        //                      << metricsManager->getMetricsMerged(periods) << std::endl;
        //        }
    } catch (const std::exception &e) {
        Corrade::Utility::printError("Fatal error: {}\n", e.what());
        result = -1;
    }

    return result;
}
