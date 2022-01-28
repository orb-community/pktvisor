/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include <csignal>
#include <functional>
#include <map>

#include <docopt/docopt.h>

#include "CoreRegistry.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include <spdlog/sinks/stdout_color_sinks.h>

#include "handlers/static_plugins.h"
#include "inputs/static_plugins.h"
#include "visor_config.h"

#include "GeoDB.h"
#include "handlers/net/NetStreamHandler.h"
#include "inputs/sflow/SflowInputStream.h"

static const char USAGE[] =
   R"(pktvisor-sflow
   Usage:
     pktvisor-sflow [options] PCAP
     pktvisor-sflow (-h | --help)
     pktvisor-sflow --version

   Summarize a sflow pcap file. The result will be written to stdout in JSON format, while console logs will be printed
   to stderr.

   Options:
     --max-deep-sample N   Never deep sample more than N% of streams (an int between 0 and 100) [default: 100]
     --periods P           Hold this many 60 second time periods of history in memory. Use 1 to summarize all data. [default: 5]
     -h --help             Show this screen
     --version             Show version
     -v                    Verbose log output
     --geo-city FILE       GeoLite2 City database to use for IP to Geo mapping (if enabled)
     --geo-asn FILE        GeoLite2 ASN database to use for IP to ASN mapping (if enabled)
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
   int result{0};

   std::map<std::string, docopt::value> args = docopt::docopt(USAGE,
       {argv + 1, argv + argc},
       true,           // show help if requested
       VISOR_VERSION); // version string

   auto logger = spdlog::stderr_color_mt("visor");
   if (args["-v"].asBool()) {
       logger->set_level(spdlog::level::debug);
   }

   CoreRegistry mgrs;

   std::signal(SIGINT, signal_handler);
   std::signal(SIGTERM, signal_handler);

   int sample_rate = 100;
   if (args["--max-deep-sample"]) {
       sample_rate = (int)args["--max-deep-sample"].asLong();
       if (sample_rate != 100) {
           logger->info("Using maximum deep sample rate: {}%", sample_rate);
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

   visor::Config window_config;
   window_config.config_set<uint64_t>("num_periods", periods);
   window_config.config_set<uint64_t>("deep_sample_rate", sample_rate);

   try {

       initialize_geo(args["--geo-city"], args["--geo-asn"]);

       auto input_stream = std::make_unique<input::sflow::SflowInputStream>("sflow");
       input_stream->config_set("pcap_file", args["PCAP"].asString());

       json j;
       input_stream->info_json(j["info"]);
       logger->info("{}", j.dump(4));

       mgrs.input_manager()->module_add(std::move(input_stream));
       auto [input_stream_, stream_mgr_lock] = mgrs.input_manager()->module_get_locked("sflow");
       stream_mgr_lock.unlock();
       auto sflow_stream = dynamic_cast<input::sflow::SflowInputStream *>(input_stream_);

       shutdown_handler = [&]([[maybe_unused]] int signal) {
           sflow_stream->stop();
           logger->flush();
       };

       handler::net::NetStreamHandler *net_handler{nullptr};
       {
           auto handler_module = std::make_unique<handler::net::NetStreamHandler>("net", sflow_stream, &window_config);
           handler_module->config_set("recorded_stream", true);
           handler_module->start();
           mgrs.handler_manager()->module_add(std::move(handler_module));
           auto [handler, handler_mgr_lock] = mgrs.handler_manager()->module_get_locked("net");
           handler_mgr_lock.unlock();
           net_handler = dynamic_cast<handler::net::NetStreamHandler *>(handler);
       }

       // blocking
       sflow_stream->start();

       json result;
       if (periods == 1) {
           // in summary mode we output a single summary of stats
           net_handler->window_json(result["1m"], 0, false);
       } else {
           // otherwise, merge the max time window available
           auto key = fmt::format("{}m", periods);
           net_handler->window_json(result[key], periods, true);
       }
       std::cout << result.dump() << std::endl;

       shutdown_handler(SIGUSR1);

   } catch (const std::exception &e) {
       logger->error("Fatal error: {}", e.what());
       result = -1;
   }

   return result;
}
