/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include <csignal>
#include <functional>

#include "CoreServer.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "Policies.h"
#include "handlers/static_plugins.h"
#include "inputs/static_plugins.h"
#include "visor_config.h"
#include <Corrade/Utility/ConfigurationGroup.h>
#include <docopt/docopt.h>
#include <resolv.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/syslog_sink.h>
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

#include "GeoDB.h"
#include "timer.hpp"

static const char USAGE[] =
    R"(pktvisord.
    Usage:
      pktvisord [options] [IFACE]
      pktvisord (-h | --help)
      pktvisord --version

    pktvisord summarizes data streams and exposes a REST API control plane for configuration and metrics.

    pktvisord operation is configured via Taps and Collection Policies. Taps abstract the process of "tapping into"
    input streams with templated configuration while Policies use Taps to instantiate and configure Input and Stream
    Handlers to analyze and summarize stream data, which is then made available for collection via REST API.

    Taps and Collection Policies may be created by passing the appropriate YAML configuration file to
    --config, and/or by enabling the admin REST API with --admin-api and using the appropriate endpoints.

    Alternatively, for simple use cases you may specify IFACE, which is either a network interface or an
    IP address (4 or 6). If this is specified, "default" Tap and Collection Policies will be created with
    a "pcap" input stream on the specified interfaced, along with the built in "net", "dns", and "pcap"
    Stream Handler modules attached. Note that this feature may be deprecated in the future.

    For more documentation, see https://pktvisor.dev

    Base Options:
      -d                          Daemonize; fork and continue running in the background [default: false]
      -h --help                   Show this screen
      -v                          Verbose log output
      --no-track                  Don't send lightweight, anonymous usage metrics
      --version                   Show version
    Web Server Options:
      -l HOST                     Run web server on the given host or IP [default: localhost]
      -p PORT                     Run web server on the given port [default: 10853]
      --tls                       Enable TLS on the web server
      --tls-cert FILE             Use given TLS cert. Required if --tls is enabled.
      --tls-key FILE              Use given TLS private key. Required if --tls is enabled.
      --admin-api                 Enable admin REST API giving complete control plane functionality [default: false]
                                  When not specified, the exposed API is read-only access to module status and metrics.
                                  When specified, write access is enabled for all modules.
    Geo Options:
      --geo-city FILE             GeoLite2 City database to use for IP to Geo mapping
      --geo-asn FILE              GeoLite2 ASN database to use for IP to ASN mapping
    Configuration:
      --config FILE               Use specified YAML configuration to configure options, Taps, and Collection Policies
                                  Please see https://pktvisor.dev for more information
    Modules:
      --module-list               List all modules which have been loaded (builtin and dynamic)
      --module-load FILE          Load the specified dynamic module
      --module-dir DIR            Set module search path
    Logging Options:
      --log-file FILE             Log to the given output file name
      --syslog                    Log to syslog
    Prometheus Options:
      --prometheus                Ignored, Prometheus output always enabled (left for backwards compatibility)
      --prom-instance ID          Optionally set the 'instance' label to given ID
    Handler Module Defaults:
      --max-deep-sample N         Never deep sample more than N% of streams (an int between 0 and 100) [default: 100]
      --periods P                 Hold this many 60 second time periods of history in memory [default: 5]
    pcap Input Module Options: (applicable to default policy when IFACE is specified only)
      -b BPF                      Filter packets using the given tcpdump compatible filter expression. Example: "port 53"
      -H HOSTSPEC                 Specify subnets (comma separated) to consider HOST, in CIDR form. In live capture this
                                  /may/ be detected automatically from capture device but /must/ be specified for pcaps.
                                  Example: "10.0.1.0/24,10.0.2.1/32,2001:db8::/64"
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

struct CmdOptions
{
    bool daemon{false};
    bool syslog{false};
    bool verbose{false};
    bool no_track{false};
    bool prometheus{false};
    std::pair<bool, std::string> log_file{false, ""};
    std::pair<bool, std::string> prom_instance{false, ""};
    std::pair<bool, std::string> geo_city{false, ""};
    std::pair<bool, std::string> geo_asn{false, ""};
    std::pair<bool, unsigned int> max_deep_sample{false, 0};
    std::pair<bool, unsigned int> periods{false, 0};
    std::pair<bool, YAML::Node> config;

    struct WebServer
    {
        bool tls_support{false};
        bool admin_api{false};
        std::pair<bool, unsigned int> port{false, 0};
        std::pair<bool, std::string> host{false, ""};
        std::pair<bool, std::string> tls_cert{false, ""};
        std::pair<bool, std::string> tls_key{false, ""};
    };
    WebServer web_server;

    struct Module
    {
        bool list{false};
        std::pair<bool, std::string> load{false, ""};
        std::pair<bool, std::string> dir{false, ""};
    };
    Module module;
};

CmdOptions fill_cmd_options(std::map<std::string, docopt::value> args)
{
    CmdOptions options;
    YAML::Node config;
    // local config file
    options.config.first = false;
    if (args["--config"]) {
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

            options.config = std::make_pair(true, config_file);

            if (config_file["visor"]["config"] && config_file["visor"]["config"].IsMap()) {
                config = config_file["visor"]["config"];
            }
        } catch (std::runtime_error &e) {
            exit(EXIT_FAILURE);
        }
    }

    options.verbose = (config["verbose"] && config["verbose"].as<bool>()) || args["-v"].asBool();
    options.daemon = (config["daemon"] && config["daemon"].as<bool>()) || args["-d"].asBool();
    options.syslog = (config["syslog"] && config["syslog"].as<bool>()) || args["--syslog"].asBool();
    options.no_track = (config["no-track"] && config["no-track"].as<bool>()) || args["--no-track"].asBool();
    options.prometheus = (config["prometheus"] && config["prometheus"].as<bool>()) || args["--prometheus"].asBool();

    if (args["--log-file"]) {
        options.log_file = std::make_pair(true,args["--log-file"].asString());
    } else if (config["log-file"]) {
        options.log_file = std::make_pair(true,config["log-file"].as<std::string>());
    }

    if (args["--prom-instance"]) {
        options.prom_instance = std::make_pair(true,args["--prom-instance"].asString());
    } else if (config["prom-instance"]) {
        options.prom_instance = std::make_pair(true,config["prom-instance"].as<std::string>());
    }

    if (args["--geo-city"]) {
        options.geo_city = std::make_pair(true,args["--geo-city"].asString());
    } else if (config["geo-city"]) {
        options.geo_city = std::make_pair(true,config["geo-city"].as<std::string>());
    }

    if (args["--geo-asn"]) {
        options.geo_asn = std::make_pair(true,args["--geo-asn"].asString());
    } else if (config["geo-asn"]) {
        options.geo_asn = std::make_pair(true,config["geo-asn"].as<std::string>());
    }

    if (args["--max-deep-sample"]) {
        options.max_deep_sample = std::make_pair(true,static_cast<unsigned int>(args["--max-deep-sample"].asLong()));
    } else if (config["max-deep-sample"]) {
        options.max_deep_sample = std::make_pair(true,config["max-deep-sample"].as<unsigned int>());
    }

    if (args["--periods"]) {
        options.max_deep_sample = std::make_pair(true,static_cast<unsigned int>(args["--periods"].asLong()));
    } else if (config["periods"]) {
        options.max_deep_sample = std::make_pair(true,config["periods"].as<unsigned int>());
    }

    options.web_server.tls_support = (config["tls"] && config["tls"].as<bool>()) || args["--tls"].asBool();
    options.web_server.admin_api = (config["admin-api"] && config["admin-api"].as<bool>()) || args["--admin-api"].asBool();

    if (args["-p"]) {
        options.web_server.port = std::make_pair(true,static_cast<unsigned int>(args["-p"].asLong()));
    } else if (config["port"]) {
        options.web_server.port = std::make_pair(true,config["port"].as<unsigned int>());
    }

    if (args["-l"]) {
        options.web_server.host = std::make_pair(true,args["-l"].asString());
    } else if (config["host"]) {
        options.web_server.host = std::make_pair(true,config["host"].as<std::string>());
    }

    if (args["--tls-cert"]) {
        options.web_server.tls_cert = std::make_pair(true,args["--tls-cert"].asString());
    } else if (config["tls-cert"]) {
        options.web_server.tls_cert = std::make_pair(true,config["tls-cert"].as<std::string>());
    }

    if (args["--tls-key"]) {
        options.web_server.host = std::make_pair(true,args["--tls-key"].asString());
    } else if (config["tls-key"]) {
        options.web_server.tls_key = std::make_pair(true,config["tls-key"].as<std::string>());
    }

    options.module.list = (config["module-list"] && config["module-list"].as<bool>()) || args["--module-list"].asBool();

    if (args["--module-load"]) {
        options.module.load = std::make_pair(true,args["--module-load"].asString());
    } else if (config["module-load"]) {
        options.module.load = std::make_pair(true,config["module-load"].as<std::string>());
    }

    if (args["--module-dir"]) {
        options.module.dir = std::make_pair(true,args["--module-dir"].asString());
    } else if (config["module-dir"]) {
        options.module.dir = std::make_pair(true,config["module-dir"].as<std::string>());
    }
    return options;
}

void initialize_geo(const std::string &city, const std::string &asn)
{
    if (!city.empty()) {
        geo::GeoIP().enable(city);
    }
    if (!asn.empty()) {
        geo::GeoASN().enable(asn);
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
        iface: "{}"
        host_spec: "{}"
  policies:
    default:
      kind: collection
      input:
        tap: default
        input_type: pcap
        config:
          bpf: "{}"
      handlers:
        window_config:
          num_periods: {}
          deep_sample_rate: {}
        modules:
          net:
            type: net
          dhcp:
            type: dhcp
          dns:
            type: dns
          pcap_stats:
            type: pcap
)";

int main(int argc, char *argv[])
{
    std::map<std::string, docopt::value> args = docopt::docopt(USAGE,
        {argv + 1, argv + argc},
        true,           // show help if requested
        VISOR_VERSION); // version string

    auto options = fill_cmd_options(args);

    if (options.daemon) {
        // before we daemonize, if they are using a log file, ensure it can be opened
        if (options.log_file.first) {
            try {
                auto logger_probe = spdlog::basic_logger_mt("pktvisor-log-probe", options.log_file.second);
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
    if (options.log_file.first) {
        try {
            logger = spdlog::basic_logger_mt("visor", options.log_file.second);
            spdlog::flush_every(std::chrono::seconds(3));
        } catch (const spdlog::spdlog_ex &ex) {
            std::cerr << "Log init failed: " << ex.what() << std::endl;
            exit(EXIT_FAILURE);
        }
    } else if (options.syslog) {
        logger = spdlog::syslog_logger_mt("visor", "pktvisord", LOG_PID, LOG_DAEMON);
    } else {
        logger = spdlog::stdout_color_mt("visor");
    }
    if (options.verbose) {
        logger->set_level(spdlog::level::debug);
    }

    // modules
    CoreRegistry registry;
    if (options.module.dir.first) {
        registry.input_plugin_registry()->setPluginDirectory(options.module.dir.second);
        registry.handler_plugin_registry()->setPluginDirectory(options.module.dir.second);
    }
    if (options.module.load.first) {
        auto meta = registry.input_plugin_registry()->metadata(options.module.load.second);
        if (!meta) {
            logger->error("failed to load plugin: {}", options.module.load.second);
            exit(EXIT_FAILURE);
        }
        if (!meta->data().hasValue("type") || (meta->data().value("type") != "handler" && meta->data().value("type") != "input")) {
            logger->error("plugin configuration metadata did not specify a valid plugin type", options.module.load.second);
            exit(EXIT_FAILURE);
        }
        if (meta->data().value("type") == "input") {
            auto result = registry.input_plugin_registry()->load(options.module.load.second);
            if (result != Corrade::PluginManager::LoadState::Loaded) {
                logger->error("failed to load input plugin: {}", result);
                exit(EXIT_FAILURE);
            }
        }
        else if (meta->data().value("type") == "handler") {
            auto result = registry.handler_plugin_registry()->load(options.module.load.second);
            if (result != Corrade::PluginManager::LoadState::Loaded) {
                logger->error("failed to load input handler plugin: {}", result);
                exit(EXIT_FAILURE);
            }
        }
    }
    if (options.module.list) {
        for (auto &p : registry.input_plugin_registry()->pluginList()) {
            logger->info("input: {}", p);
        }
        for (auto &p : registry.handler_plugin_registry()->pluginList()) {
            logger->info("handler: {}", p);
        }
        exit(EXIT_SUCCESS);
    }

    logger->info("{} starting up", VISOR_VERSION);

    // if we are demonized, change to root directory now that (potentially) logs are open
    if (options.daemon) {
        chdir("/");
    }

    PrometheusConfig prom_config;
    prom_config.default_path = "/metrics";
    if (options.prom_instance.first) {
        prom_config.instance_label = options.prom_instance.second;
    }

    HttpConfig http_config;
    http_config.read_only = !options.web_server.admin_api;
    if (options.web_server.tls_support) {
        http_config.tls_enabled = true;
        if (!options.web_server.tls_key.first || !options.web_server.tls_cert.first) {
            logger->error("you must specify --tls-key and --tls-cert to use --tls");
            exit(EXIT_FAILURE);
        }
        http_config.key = options.web_server.tls_key.second;
        http_config.cert = options.web_server.tls_cert.second;
        logger->info("Enabling TLS with cert {} and key {}", http_config.key, http_config.cert);
    }

    std::unique_ptr<CoreServer> svr;
    try {
        svr = std::make_unique<CoreServer>(&registry, logger, http_config, prom_config);
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
    if (options.config.first) {
        //pass to CoreManagers
        svr->registry()->configure_from_yaml(options.config.second);
    }

    shutdown_handler = [&]([[maybe_unused]] int signal) {
        logger->info("Shutting down");
        logger->flush();
        svr->stop();
        logger->flush();
    };
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    auto host = options.web_server.host.second;
    auto port = options.web_server.port.second;

    unsigned int sample_rate = 100;
    if (options.max_deep_sample.first) {
        sample_rate = options.max_deep_sample.second;
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
    if (!options.no_track) {
        static timer timer_thread{1min};
        // once at start up
        usage_metrics();
        // once per day
        timer_handle = timer_thread.set_interval(24h, usage_metrics);
    }

    unsigned int periods = options.periods.second;

    try {
        initialize_geo(options.geo_asn.second, options.geo_asn.second);
    } catch (const std::exception &e) {
        logger->error("Fatal error: {}", e.what());
        exit(EXIT_FAILURE);
    }

    if (args["IFACE"]) {
        // pcap command line functionality, create default policy
        try {
            std::string bpf;
            if (args["-b"]) {
                bpf = args["-b"].asString();
            }

            std::string host_spec;
            if (args["-H"]) {
                host_spec = args["-H"].asString();
            }

            auto policy_str = fmt::format(default_tap_policy, args["IFACE"].asString(), host_spec, bpf, periods, sample_rate);
            logger->debug(policy_str);
            svr->registry()->configure_from_str(policy_str);

        } catch (const std::exception &e) {
            logger->error(e.what());
            logger->info("exit with failure");
            exit(EXIT_FAILURE);
        }
    } else if (!options.web_server.admin_api) {
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
    return EXIT_SUCCESS;
}
