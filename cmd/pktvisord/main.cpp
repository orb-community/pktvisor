/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include <csignal>
#include <functional>

#include "CoreServer.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "handlers/static_plugins.h"
#include "inputs/static_plugins.h"
#include "visor_config.h"
#include <docopt/docopt.h>
#include <resolv.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/syslog_sink.h>
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

#include "GeoDB.h"
#include "handlers/dns/DnsStreamHandler.h"
#include "handlers/net/NetStreamHandler.h"
#include "handlers/pcap/PcapStreamHandler.h"
#include "inputs/pcap/PcapInputStream.h"
#include "timer.hpp"

static const char USAGE[] =
    R"(pktvisord.
    Usage:
      pktvisord [options] [IFACE]
      pktvisord (-h | --help)
      pktvisord --version

    pktvisord summarizes data streams and exposes a REST API control plane for configuration and metrics.

    pktvisord operation is configured via Taps and Collection Policies. The former set up the available
    input streams while the latter instantiate Taps and Stream Handlers to analyze and summarize
    the stream data.

    Taps and Collection Policies may be created by passing the appropriate YAML configuration file to
    --config, and/or by enabling the admin REST API with --admin-api and using the appropriate endpoints.

    Alternatively, for simple use cases you may specify IFACE, which is either a network interface or an
    IP address (4 or 6). If this is specified, "default" Tap and Collection Policies will be created with
    a "pcap" input stream on the specified interfaced, along with the built in "net", "dns", and "pcap"
    Stream Handler modules attached. Note that this feature may be deprecated in the future.

    For more documentation, see https://pktvisor.dev

    Base Options:
      -d                    Daemonize; fork and continue running in the background [default: false]
      -h --help             Show this screen
      -v                    Verbose log output
      --no-track            Don't send lightweight, anonymous usage metrics
      --version             Show version
    Web Server Options:
      -l HOST               Run web server on the given host or IP [default: localhost]
      -p PORT               Run web server on the given port [default: 10853]
      --tls                 Enable TLS on the web server
      --tls-cert FILE       Use given TLS cert. Required if --tls is enabled.
      --tls-key FILE        Use given TLS private key. Required if --tls is enabled.
      --admin-api           Enable admin REST API giving complete control plane functionality [default: false]
                            When not specified, the exposed API is read-only access to module status and metrics.
                            When specified, write access is enabled for all modules.
    Geo Options:
      --geo-city FILE       GeoLite2 City database to use for IP to Geo mapping
      --geo-asn FILE        GeoLite2 ASN database to use for IP to ASN mapping
    Configuration:
      --config FILE         Use specified YAML configuration to configure options, Taps, and Collection Policies
                            Please see https://pktvisor.dev for more information
    Logging Options:
      --log-file FILE       Log to the given output file name
      --syslog              Log to syslog
    Prometheus Options:
      --prometheus          Enable native Prometheus metrics at path /metrics
      --prom-instance ID    Optionally set the 'instance' label to given ID
    Handler Module Defaults:
      --max-deep-sample N   Never deep sample more than N% of streams (an int between 0 and 100) [default: 100]
      --periods P           Hold this many 60 second time periods of history in memory [default: 5]
    pcap Input Module Options: (applicable to default policy when IFACE is specified only)
      -b BPF                Filter packets using the given tcpdump compatible filter expression. Example: "port 53"
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

// adapted from LPI becomeDaemon()
int daemonize()
{

    switch (auto pid = fork()) {
    case -1:
        return -1;
    case 0:
        // Child falls through...
        break;
    default:
        // while parent terminates
        spdlog::get("pktvisor-daemon")->info("daemonized to PID {}", pid);
        _exit(EXIT_SUCCESS);
    }

    // Become leader of new session
    if (setsid() == -1) {
        spdlog::get("pktvisor-daemon")->error("setsid() fail");
        return -1;
    }

    // Clear file mode creation mask
    umask(0);

    // Reopen standard fd's to /dev/null
    close(STDIN_FILENO);

    int fd = open("/dev/null", O_RDWR);

    if (fd != STDIN_FILENO) {
        spdlog::get("pktvisor-daemon")->error("open() fail");
        return -1;
    }
    if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO) {
        spdlog::get("pktvisor-daemon")->error("dup2 fail (STDOUT)");
        return -1;
    }
    if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO) {
        spdlog::get("pktvisor-daemon")->error("dup2 fail (STDERR)");
        return -1;
    }

    return 0;
}

auto default_tap_policy = R"(
version: "1.0"

visor:
  taps:
    default:
      input_type: pcap
      config:
        iface: {}
        host_spec: {}
  collection:
    default:
      input:
        tap: default
        config:
          bpf: {}
      handlers:
        window_config:
          num_periods: {}
          deep_sample_rate: {}
        modules:
          default_net:
            type: net
          default_dns:
            type: dns
          default_pcap:
            type: pcap
)";

int main(int argc, char *argv[])
{

    std::map<std::string, docopt::value> args = docopt::docopt(USAGE,
        {argv + 1, argv + argc},
        true,           // show help if requested
        VISOR_VERSION); // version string

    bool daemon{args["-d"].asBool()};
    if (daemon) {
        // before we daemonize, if they are using a log file, ensure it can be opened
        if (args["--log-file"]) {
            try {
                auto logger_probe = spdlog::basic_logger_mt("pktvisor-log-probe", args["--log-file"].asString());
            } catch (const spdlog::spdlog_ex &ex) {
                std::cerr << "Log init failed: " << ex.what() << std::endl;
                exit(EXIT_FAILURE);
            }
        }
        auto dlogger = spdlog::stderr_color_st("pktvisor-daemon");
        dlogger->flush_on(spdlog::level::info);
        if (daemonize()) {
            dlogger->error("failed to daemonize");
            exit(EXIT_FAILURE);
        }
    }

    std::shared_ptr<spdlog::logger> logger;
    spdlog::flush_on(spdlog::level::err);
    if (args["--log-file"]) {
        try {
            logger = spdlog::basic_logger_mt("visor", args["--log-file"].asString());
            spdlog::flush_every(std::chrono::seconds(3));
        } catch (const spdlog::spdlog_ex &ex) {
            std::cerr << "Log init failed: " << ex.what() << std::endl;
            exit(EXIT_FAILURE);
        }
    } else if (args["--syslog"].asBool()) {
        logger = spdlog::syslog_logger_mt("visor", "pktvisord", LOG_PID, LOG_DAEMON);
    } else {
        logger = spdlog::stdout_color_mt("visor");
    }
    if (args["-v"].asBool()) {
        logger->set_level(spdlog::level::debug);
    }

    logger->info("{} starting up", VISOR_VERSION);

    // if we are demonized, change to root directory now that (potentially) logs are open
    if (daemon) {
        chdir("/");
    }

    PrometheusConfig prom_config;
    if (args["--prometheus"].asBool()) {
        prom_config.path = "/metrics";
        if (args["--prom-instance"]) {
            prom_config.instance = args["--prom-instance"].asString();
        }
    }

    HttpConfig http_config;
    http_config.read_only = !args["--admin-api"].asBool();
    if (args["--tls"].asBool()) {
        http_config.tls_enabled = true;
        if (!args["--tls-key"] || !args["--tls-cert"]) {
            logger->error("you must specify --tls-key and --tls-cert to use --tls");
            exit(EXIT_FAILURE);
        }
        http_config.key = args["--tls-key"].asString();
        http_config.cert = args["--tls-cert"].asString();
        logger->info("Enabling TLS with cert {} and key {}", http_config.key, http_config.cert);
    }

    std::unique_ptr<CoreServer> svr;
    try {
        svr = std::make_unique<CoreServer>(logger, http_config, prom_config);
    } catch (const std::exception &e) {
        logger->error(e.what());
        logger->info("exit with failure");
        exit(EXIT_FAILURE);
    }
    svr->set_http_logger([&logger](const auto &req, const auto &res) {
        logger->info("REQUEST: {} {} {}", req.method, req.path, res.status);
        if (res.status == 500) {
            logger->error(res.body);
        }
    });

    // local config file
    if (args["--config"]) {
        logger->info("loading config file: {}", args["--config"].asString());
        YAML::Node config_file;
        // look for local options
        try {
            config_file = YAML::LoadFile(args["--config"].asString());

            if (!config_file.IsMap() || !config_file["visor"]) {
                throw std::runtime_error("invalid schema");
            }
            if (!config_file["version"] || !config_file["version"].IsScalar() || config_file["version"].as<std::string>() != "1.0") {
                throw std::runtime_error("missing or unsupported version");
            }

            if (config_file["visor"]["config"] && config_file["visor"]["config"].IsMap()) {
                // todo more config items
                auto config = config_file["visor"]["config"];
                if (config["verbose"] && config["verbose"].as<bool>()) {
                    logger->set_level(spdlog::level::debug);
                }
            }

            // then pass to CoreManagers
            svr->registry()->configure_from_file(args["--config"].asString());

        } catch (std::runtime_error &e) {
            logger->error("configuration error: {}", e.what());
            exit(EXIT_FAILURE);
        }

    }

    shutdown_handler = [&]([[maybe_unused]] int signal) {
        logger->info("Shutting down");
        logger->flush();
        svr->stop();
        logger->flush();
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
        exit(EXIT_FAILURE);
    }

    if (args["IFACE"]) {
        // pcap command line functionality
        try {
            std::string bpf;
            if (args["-b"]) {
                bpf = args["-b"].asString();
            }

            std::string host_spec;
            if (args["-H"]) {
                host_spec = args["-H"].asString();
            }

            input_stream->config_set("iface", args["IFACE"].asString());
            input_stream->config_set("bpf", bpf);
            input_stream->config_set("host_spec", host_spec);

            window_config.config_set<uint64_t>("num_periods", periods);
            window_config.config_set<uint64_t>("deep_sample_rate", sample_rate);

        } catch (const std::exception &e) {
            logger->error(e.what());
            logger->info("exit with failure");
            exit(EXIT_FAILURE);
        }
    } else if (!args["--admin-api"].asBool()) {
        // if they didn't specify pcap target, or config file, or admin api then there is nothing to do
        logger->error("Nothing to do: specify --admin-api or IFACE.");
        std::cerr << USAGE << std::endl;
        exit(EXIT_FAILURE);
    }

    try {
        svr->start(host.c_str(), port);
    } catch (const std::exception &e) {
        logger->error(e.what());
        logger->info("exit with failure");
        exit(EXIT_FAILURE);
    }

    logger->info("exit with success");
    exit(EXIT_SUCCESS);
}
