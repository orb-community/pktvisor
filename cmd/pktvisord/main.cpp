#include <iostream>
#include <map>

#include <cpp-httplib/httplib.h>
#include <docopt/docopt.h>

#include "HandlerManager.h"
#include "InputManager.h"

#include "config.h"

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

void setupRoutes(httplib::Server &svr)
{
}

int main(int argc, char *argv[])
{
    int result{0};

    std::map<std::string, docopt::value> args = docopt::docopt(USAGE,
        {argv + 1, argv + argc},
        true,              // show help if requested
        PKTVISOR_VERSION); // version string

    httplib::Server svr;

    pktvisor::InputManager input_manager(svr);
    pktvisor::HandlerManager handler_manager(svr);

    auto host = args["-l"].asString();
    auto port = args["-p"].asLong();

    std::thread httpThread([&svr, host, port] {
        if (!svr.listen(host.c_str(), port)) {
            throw std::runtime_error("unable to listen");
        }
    });

    std::cerr << "Metrics web server listening on " << host << ":" << port << std::endl;

    try {

    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        result = -1;
    }
    svr.stop();
    httpThread.join();

    return result;
}
