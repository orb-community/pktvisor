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
#include <spdlog/sinks/stdout_color_sinks.h>

#include "handlers/static_plugins.h"
#include "inputs/static_plugins.h"
#include "vizer_config.h"

#include "GeoDB.h"
#include "handlers/dns/DnsStreamHandler.h"
#include "handlers/net/NetStreamHandler.h"
#include "inputs/pcap/PcapInputStream.h"

static const char USAGE[] =
    R"(pktvisor-pcap
    Usage:
      pktvisor-pcap [-b BPF] [-H HOSTSPEC] [--geo-city FILE] [--geo-asn FILE] [--max-deep-sample N] [--periods P] PCAP
      pktvisor-pcap (-h | --help)
      pktvisor-pcap --version

    Summarize a pcap file

    Options:
      --max-deep-sample N   Never deep sample more than N% of streams (an int between 0 and 100) [default: 100]
      --periods P           Hold this many 60 second time periods of history in memory. Use 1 to summarize all data. [default: 5]
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

using namespace vizer;

typedef Corrade::PluginManager::Manager<InputModulePlugin> InputPluginRegistry;
typedef Corrade::PluginManager::Manager<HandlerModulePlugin> HandlerPluginRegistry;
typedef Corrade::Containers::Pointer<InputModulePlugin> InputPluginPtr;
typedef Corrade::Containers::Pointer<HandlerModulePlugin> HandlerPluginPtr;

void initialize_geo(const docopt::value &city, const docopt::value &asn)
{
    if (city) {
        geo::GeoIP().enable(city.asString());
    }
    if (asn) {
        geo::GeoASN().enable(city.asString());
    }
}

int main(int argc, char *argv[])
{
    int result{0};

    auto console = spdlog::stdout_color_mt("console");
    auto err_logger = spdlog::stderr_color_mt("stderr");

    std::map<std::string, docopt::value> args = docopt::docopt(USAGE,
        {argv + 1, argv + argc},
        true,           // show help if requested
        VIZER_VERSION); // version string

    // inputs
    InputPluginRegistry input_registry;
    auto input_manager = std::make_unique<InputStreamManager>();
    std::vector<InputPluginPtr> input_plugins;

    // initialize input plugins
    for (auto &s : input_registry.pluginList()) {
        InputPluginPtr mod = input_registry.instantiate(s);
        err_logger->info("Load input plugin: {} {}", mod->name(), mod->pluginInterface());
        mod->init_module(input_manager.get());
        input_plugins.emplace_back(std::move(mod));
    }

    // handlers
    HandlerPluginRegistry handler_registry;
    auto handler_manager = std::make_unique<HandlerManager>();
    std::vector<HandlerPluginPtr> handler_plugins;

    // initialize handler plugins
    for (auto &s : handler_registry.pluginList()) {
        HandlerPluginPtr mod = handler_registry.instantiate(s);
        err_logger->info("Load handler plugin: {} {}", mod->name(), mod->pluginInterface());
        mod->init_module(input_manager.get(), handler_manager.get());
        handler_plugins.emplace_back(std::move(mod));
    }

    shutdown_handler = [&]([[maybe_unused]] int signal) {
        // gracefully close all inputs and handlers
        auto [input_modules, im_lock] = input_manager->module_get_all_locked();
        for (auto &[name, mod] : input_modules) {
            mod->stop();
        }
        auto [handler_modules, hm_lock] = handler_manager->module_get_all_locked();
        for (auto &[name, mod] : handler_modules) {
            mod->stop();
        }
    };

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    int sample_rate = 100;
    if (args["--max-deep-sample"]) {
        sample_rate = (int)args["--max-deep-sample"].asLong();
        if (sample_rate != 100) {
            err_logger->info("Using maximum deep sample rate: {}%", sample_rate);
        }
    }

    std::string bpf;
    if (args["-b"]) {
        bpf = args["-b"].asString();
    }

    std::string host_spec;
    if (args["-H"]) {
        host_spec = args["-H"].asString();
    }

    long periods = args["--periods"].asLong();

    try {

        initialize_geo(args["--geo-city"], args["--geo-asn"]);

        auto input_stream = std::make_unique<input::pcap::PcapInputStream>("pcap");
        input_stream->config_set("pcap_file", args["PCAP"].asString());
        input_stream->config_set("bpf", bpf);
        input_stream->config_set("host_spec", host_spec);

        input_stream->parse_host_spec();
        console->info("{}", input_stream->config_json().dump(4));
        console->info("{}", input_stream->info_json().dump(4));

        input_manager->module_add(std::move(input_stream), false);
        auto [input_stream_, stream_mgr_lock] = input_manager->module_get_locked("pcap");
        stream_mgr_lock.unlock();
        auto pcap_stream = dynamic_cast<input::pcap::PcapInputStream *>(input_stream_);

        handler::net::NetStreamHandler *net_handler{nullptr};
        {
            auto handler_module = std::make_unique<handler::net::NetStreamHandler>("net", pcap_stream, periods, sample_rate);
            handler_manager->module_add(std::move(handler_module));
            auto [handler, handler_mgr_lock] = handler_manager->module_get_locked("net");
            handler_mgr_lock.unlock();
            net_handler = dynamic_cast<handler::net::NetStreamHandler *>(handler);
        }
        handler::dns::DnsStreamHandler *dns_handler{nullptr};
        {
            auto handler_module = std::make_unique<handler::dns::DnsStreamHandler>("dns", pcap_stream, periods, sample_rate);
            handler_manager->module_add(std::move(handler_module));
            auto [handler, handler_mgr_lock] = handler_manager->module_get_locked("dns");
            handler_mgr_lock.unlock();
            dns_handler = dynamic_cast<handler::dns::DnsStreamHandler *>(handler);
        }

        pcap_stream->start();

        json result;
        if (periods == 1) {
            // in summary mode we output a single summary of stats
            net_handler->to_json(result, 0, false);
            dns_handler->to_json(result, 0, false);
        } else {
            // otherwise, merge the max time window available
            net_handler->to_json(result, periods, true);
            dns_handler->to_json(result, periods, true);
        }
        console->info("{}", result.dump());
        shutdown_handler(SIGUSR1);

    } catch (const std::exception &e) {
        err_logger->error("Fatal error: {}", e.what());
        result = -1;
    }

    return result;
}
