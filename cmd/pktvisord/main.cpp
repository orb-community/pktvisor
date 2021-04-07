/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include <csignal>
#include <functional>

#include "CoreServer.h"
#include "handlers/static_plugins.h"
#include "inputs/static_plugins.h"
#include "visor_config.h"
#include <docopt/docopt.h>
#include <resolv.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include "GeoDB.h"
#include "handlers/dns/DnsStreamHandler.h"
#include "handlers/net/NetStreamHandler.h"
#include "inputs/pcap/PcapInputStream.h"
#include "timer.hpp"

static const char USAGE[] =
    R"(pktvisord.
    Usage:
      pktvisord [options] [IFACE]
      pktvisord (-h | --help)
      pktvisord --version

    pktvisord summarizes data streams and exposes a REST API control plane for configuration and metrics.

    IFACE, if specified, is either a network interface or an IP address (4 or 6). If this is specified,
    a "pcap" input stream will be automatically created, with "net" and "dns" handler modules attached.

    Base Options:
      -l HOST               Run webserver on the given host or IP [default: localhost]
      -p PORT               Run webserver on the given port [default: 10853]
      --admin-api           Enable admin REST API giving complete control plane functionality [default: false]
                            When not specified, the exposed API is read-only access to summarized metrics.
                            When specified, write access is enabled for all modules.
      -h --help             Show this screen
      -v                    Verbose log output
      --no-track            Don't send lightweight, anonymous usage metrics.
      --version             Show version
      --geo-city FILE       GeoLite2 City database to use for IP to Geo mapping (if enabled)
      --geo-asn FILE        GeoLite2 ASN database to use for IP to ASN mapping (if enabled)
    Prometheus Options:
      --prometheus          Enable native Prometheus metrics at path /metrics
      --prom-instance ID    Optionally set the 'instance' tag to ID
    Handler Module Defaults:
      --max-deep-sample N   Never deep sample more than N% of streams (an int between 0 and 100) [default: 100]
      --periods P           Hold this many 60 second time periods of history in memory [default: 5]
    pcap Input Module Options:
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

using namespace visor;

void initialize_geo(const docopt::value &city, const docopt::value &asn)
{
    if (city) {
        geo::GeoIP().enable(city.asString());
    }
    if (asn) {
        geo::GeoASN().enable(asn.asString());
    }
}

int main(int argc, char *argv[])
{

    std::map<std::string, docopt::value> args = docopt::docopt(USAGE,
        {argv + 1, argv + argc},
        true,           // show help if requested
        VISOR_VERSION); // version string

    auto logger = spdlog::stdout_color_mt("pktvisor");
    if (args["-v"].asBool()) {
        logger->set_level(spdlog::level::debug);
    }

    PrometheusConfig prom_config;
    if (args["--prometheus"].asBool()) {
        prom_config.path = "/metrics";
        if (args["--prom-instance"]) {
            prom_config.instance = args["--prom-instance"].asString();
        }
    }
    CoreServer svr(!args["--admin-api"].asBool(), logger, prom_config);
    svr.set_http_logger([&logger](const auto &req, const auto &res) {
        logger->info("REQUEST: {} {} {}", req.method, req.path, res.status);
        if (res.status == 500) {
            logger->error(res.body);
        }
    });

    shutdown_handler = [&]([[maybe_unused]] int signal) {
        logger->info("Shutting down");
        svr.stop();
    };
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    auto host = args["-l"].asString();
    auto port = args["-p"].asLong();

    int sample_rate = 100;
    if (args["--max-deep-sample"]) {
        sample_rate = (int)args["--max-deep-sample"].asLong();
        if (sample_rate != 100) {
            logger->info("Using maximum deep sample rate: {}%", sample_rate);
        }
    }

    /**
     * anonymous lightweight usage metrics, to help understand project usage
     */
    std::shared_ptr<timer::interval_handle> timer_handle;
    auto usage_metrics = [&logger] {
        u_char buf[1024];
        std::string version_str{VISOR_VERSION_NUM};
        std::reverse(version_str.begin(), version_str.end());
        std::string target = version_str + ".pktvisord.metrics.pktvisor.dev.";
        logger->info("sending anonymous usage metrics (once/day, use --no-track to disable): {}", target);
        if (res_query(target.c_str(), ns_c_in, ns_t_txt, buf, 1024) < 0) {
            logger->warn("metrics send failed");
        }
    };
    if (!args["--no-track"].asBool()) {
        static timer timer_thread{1min};
        // once at start up
        usage_metrics();
        // once per day
        timer_handle = timer_thread.set_interval(24h, usage_metrics);
    }

    long periods = args["--periods"].asLong();

    try {
        initialize_geo(args["--geo-city"], args["--geo-asn"]);
    } catch (const std::exception &e) {
        logger->error("Fatal error: {}", e.what());
        exit(-1);
    }

    if (args["IFACE"]) {
        // pcap command line functionality (deprecated)
        try {
            std::string bpf;
            if (args["-b"]) {
                bpf = args["-b"].asString();
            }

            std::string host_spec;
            if (args["-H"]) {
                host_spec = args["-H"].asString();
            }

            auto input_stream = std::make_unique<input::pcap::PcapInputStream>("pcap");
            input_stream->config_set("iface", args["IFACE"].asString());
            input_stream->config_set("bpf", bpf);
            input_stream->config_set("host_spec", host_spec);

            auto input_manager = svr.input_manager();
            auto handler_manager = svr.handler_manager();

            input_manager->module_add(std::move(input_stream));
            auto [input_stream_, stream_mgr_lock] = input_manager->module_get_locked("pcap");
            stream_mgr_lock.unlock();
            auto pcap_stream = dynamic_cast<input::pcap::PcapInputStream *>(input_stream_);

            {
                auto handler_module = std::make_unique<handler::net::NetStreamHandler>("net", pcap_stream, periods, sample_rate);
                handler_manager->module_add(std::move(handler_module));
            }
            {
                auto handler_module = std::make_unique<handler::dns::DnsStreamHandler>("dns", pcap_stream, periods, sample_rate);
                handler_manager->module_add(std::move(handler_module));
            }

            json j;
            input_stream_->info_json(j["info"]);
            logger->info("{}", j.dump(4));

        } catch (const std::exception &e) {
            logger->error(e.what());
            exit(-1);
        }
    } else if (!args["--admin-api"].asBool()) {
        // if they didn't specify pcap target, or config file, or admin api then there is nothing to do
        logger->error("Nothing to do: specify --admin-api or IFACE.");
        std::cerr << USAGE << std::endl;
        exit(-1);
    }

    try {
        svr.start(host.c_str(), port);
    } catch (const std::exception &e) {
        logger->error(e.what());
        exit(-1);
    }

    return 0;
}
