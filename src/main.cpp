#include <iostream>

#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <PacketUtils.h>
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>
#include <SystemUtils.h>
#include <UdpLayer.h>
#include <IpUtils.h>

// we keep http server thread count low because we don't need high concurrency
// and we want to limit lock contention on data structures
#define CPPHTTPLIB_THREAD_POOL_COUNT 3
#include <cpp-httplib/httplib.h>
#include <docopt/docopt.h>

#include "metrics.h"
#include "pktvisor.h"
#include "querypairmgr.h"
#include "tcpsession.h"
#include "utils.h"
#include "config.h"

static const char USAGE[] =
    R"(pktvisord.
    Usage:
      pktvisord [-b BPF] [-p PORT] [-H HOSTSPEC] [--periods P] [--summary] [--geo-city FILE] [--geo-asn FILE] TARGET
      pktvisord (-h | --help)
      pktvisord --version

    pktvisord will summarize your packet streams.

    TARGET is either a network interface, an IP address (4 or 6) or a pcap file (ending in .pcap or .cap)

    Options:
      -p PORT          Run metrics webserver on the given localhost port [default: 10853]
      -b BPF           Filter packets using the given BPF string
      --geo-city FILE  GeoLite2 City database to use for IP to Geo mapping (if enabled)
      --geo-asn FILE   GeoLite2 ASN database to use for IP to ASN mapping (if enabled)
      --periods P      Hold this many 60 second time periods of history in memory [default: 5]
      --summary        Instead of a time window with P periods, summarize all packets into one bucket for entire time period.
                       Useful for executive summary of (and applicable only to) a pcap file. [default: false]
      -H HOSTSPEC      Specify subnets (comma separated) to consider HOST, in CIDR form. In live capture this /may/ be detected automatically
                       from capture device but /must/ be specified for pcaps. Example: "10.0.1.0/24,10.0.2.1/32,2001:db8::/64"
                       Specifying this for live capture will append to any automatic detection.
      -h --help        Show this screen
      --version        Show version
)";

static std::unique_ptr<pktvisor::MetricsMgr> metricsManager;
static pktvisor::QueryResponsePairMgr dnsQueryPairManager;

static pktvisor::IPv4subnetList hostIPv4;
static pktvisor::IPv6subnetList hostIPv6;
typedef std::pair<pktvisor::TcpDnsReassembly *, bool> devCookie;

// got a full DNS wire message. called from all l3 and l4.
static void onGotDnsMessage(pcpp::DnsLayer *dnsLayer, pktvisor::Direction dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowKey)
{
    assert(dnsLayer != nullptr);
    metricsManager->newDNSPacket(dnsLayer, dir, l3, l4);
    if (dnsLayer->getDnsHeader()->queryOrResponse == pktvisor::response) {
        auto xact = dnsQueryPairManager.maybeEndDnsTransaction(flowKey, dnsLayer->getDnsHeader()->transactionID);
        if (xact) {
            auto now = std::chrono::high_resolution_clock::now();
            metricsManager->newDNSXact(dnsLayer, dir, now - xact->queryStartTS);
        }
    } else {
        dnsQueryPairManager.startDnsTransaction(flowKey, dnsLayer->getDnsHeader()->transactionID);
    }
};

// called only for TCP, both IPv4 and 6
static void onGotTcpDnsMessage(pcpp::DnsLayer *dnsLayer, pktvisor::Direction dir, pcpp::ProtocolType l3, uint32_t flowKey)
{
    onGotDnsMessage(dnsLayer, dir, l3, pcpp::TCP, flowKey);
}

/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
static void onApplicationInterrupted(void *cookie)
{
    std::cout << "stopping..." << std::endl;
    devCookie *dC = (devCookie *)cookie;
    dC->second = true;
}

/**
 * Called for live and pcap
 */
static void processRawPacket(pcpp::RawPacket *rawPacket, pktvisor::TcpDnsReassembly *tcpReassembly)
{

    pcpp::ProtocolType l3, l4;
    pcpp::Packet packet(rawPacket);
    l3 = (packet.isPacketOfType(pcpp::IPv4)) ? pcpp::IPv4 : pcpp::IPv6;
    l4 = (packet.isPacketOfType(pcpp::UDP)) ? pcpp::UDP : pcpp::TCP;
    // determine packet direction by matching source/dest ips
    // note the direction may be indeterminate!
    pktvisor::Direction dir = pktvisor::unknown;
    auto IP4layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    auto IP6layer = packet.getLayerOfType<pcpp::IPv6Layer>();
    if (IP4layer) {
        for (auto &i : hostIPv4) {
            if (IP4layer->getDstIpAddress().matchSubnet(i.first, i.second)) {
                dir = pktvisor::toHost;
                break;
            } else if (IP4layer->getSrcIpAddress().matchSubnet(i.first, i.second)) {
                dir = pktvisor::fromHost;
                break;
            }
        }
    } else if (IP6layer) {
        for (auto &i : hostIPv6) {
            if (IP6layer->getDstIpAddress().matchSubnet(i.first, i.second)) {
                dir = pktvisor::toHost;
                break;
            } else if (IP6layer->getSrcIpAddress().matchSubnet(i.first, i.second)) {
                dir = pktvisor::fromHost;
                break;
            }
        }
    }
    metricsManager->newPacket(packet, dnsQueryPairManager, l4, dir, l3);
    if (packet.isPacketOfType(pcpp::UDP)) {
        pcpp::DnsLayer *dnsLayer = packet.getLayerOfType<pcpp::DnsLayer>();
        if (dnsLayer == nullptr) {
            // a UDP packet which wasn't DNS
            return;
        }
        onGotDnsMessage(dnsLayer, dir, l3, l4, pcpp::hash5Tuple(&packet));
    } else if (packet.isPacketOfType(pcpp::TCP)) {
        // get a pointer to the TCP reassembly instance and feed the packet arrived to it
        // we don't know yet if it's DNS, the reassembly manager figures that out
        tcpReassembly->getTcpReassembly()->reassemblePacket(rawPacket);
    } else {
        // unsupported layer3 protocol
    }
}

void openPcap(std::string fileName, pktvisor::TcpDnsReassembly &tcpReassembly, std::string bpfFilter = "")
{
    // open input file (pcap or pcapng file)
    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(fileName.c_str());

    // try to open the file device
    if (!reader->open())
        throw std::runtime_error("Cannot open pcap/pcapng file");

    // set BPF filter if set by the user
    if (bpfFilter != "") {
        if (!reader->setFilter(bpfFilter))
            throw std::runtime_error("Cannot set BPF filter to pcap file");
    }

    // run in a loop that reads one packet from the file in each iteration and feeds it to the TCP reassembly instance
    pcpp::RawPacket rawPacket;
    // setup initial timestamp from first packet to initiate bucketing
    if (reader->getNextPacket(rawPacket)) {
        metricsManager->setInitialShiftTS(&rawPacket);
        processRawPacket(&rawPacket, &tcpReassembly);
    }
    while (reader->getNextPacket(rawPacket)) {
        processRawPacket(&rawPacket, &tcpReassembly);
    }

    // after all packets have been read - close the connections which are still opened
    tcpReassembly.getTcpReassembly()->closeAllConnections();

    // close the reader and free its memory
    reader->close();
    delete reader;
}

/**
 * packet capture callback - called whenever a packet arrives on the live device (in live device capturing mode)
 */
static bool onLivePacketArrives(pcpp::RawPacket *rawPacket, pcpp::PcapLiveDevice *dev, void *cookie)
{
    devCookie *dC = (devCookie *)cookie;
    processRawPacket(rawPacket, dC->first);
    // false means don't stop capturing after this callback runs
    // this is controlled by onApplicationInterrupted
    return dC->second;
}

void openIface(pcpp::PcapLiveDevice *dev, pktvisor::TcpDnsReassembly &tcpReassembly, std::string bpfFilter = "")
{

    pcpp::PcapLiveDevice::DeviceConfiguration config;
    /*
     * https://www.tcpdump.org/manpages/pcap.3pcap.html
       packet buffer timeout
        If, when capturing, packets are delivered as soon as they arrive, the application capturing the packets will be woken up for each packet as it arrives, and might have to make one or more calls to the operating system to fetch each packet.
        If, instead, packets are not delivered as soon as they arrive, but are delivered after a short delay (called a "packet buffer timeout"), more than one packet can be accumulated before the packets are delivered, so that a single wakeup would be done for multiple packets, and each set of calls made to the operating system would supply multiple packets, rather than a single packet. This reduces the per-packet CPU overhead if packets are arriving at a high rate, increasing the number of packets per second that can be captured.
        The packet buffer timeout is required so that an application won't wait for the operating system's capture buffer to fill up before packets are delivered; if packets are arriving slowly, that wait could take an arbitrarily long period of time.
        Not all platforms support a packet buffer timeout; on platforms that don't, the packet buffer timeout is ignored. A zero value for the timeout, on platforms that support a packet buffer timeout, will cause a read to wait forever to allow enough packets to arrive, with no timeout. A negative value is invalid; the result of setting the timeout to a negative value is unpredictable.
        NOTE: the packet buffer timeout cannot be used to cause calls that read packets to return within a limited period of time, because, on some platforms, the packet buffer timeout isn't supported, and, on other platforms, the timer doesn't start until at least one packet arrives. This means that the packet buffer timeout should NOT be used, for example, in an interactive application to allow the packet capture loop to ``poll'' for user input periodically, as there's no guarantee that a call reading packets will return after the timeout expires even if no packets have arrived.
        The packet buffer timeout is set with pcap_set_timeout().
     */
    config.packetBufferTimeoutMs = 100;

    // try to open device
    if (!dev->open(config))
        throw std::runtime_error("Cannot open interface");

    // set BPF filter if set by the user
    if (bpfFilter != "") {
        if (!dev->setFilter(bpfFilter))
            throw std::runtime_error("Cannot set BPF filter to interface");
        std::cout << "BPF: " << bpfFilter << std::endl;
    }

    printf("Starting packet capture on '%s'...\n", dev->getName());

    // register the on app close event to print summary stats on app termination
    devCookie dC = {&tcpReassembly, false};
    pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &dC);

    metricsManager->setInitialShiftTS();

    // start capturing packets
    bool capturing = true;
    while (capturing) {
        auto result = dev->startCaptureBlockingMode(onLivePacketArrives, &dC, 2);
        switch (result) {
        case 0:
            // error
            capturing = false;
            break;
        case -1:
            // timeout expired, see if we should still capture. dC.second answers question "stopping?"
            capturing = !dC.second;
            break;
        case 1:
            // onpacketarrived told us to stop
            capturing = false;
            break;
        }
    }

    // stop capturing and close the live device
    dev->stopCapture();
    dev->close();

    // close all connections which are still opened
    tcpReassembly.getTcpReassembly()->closeAllConnections();
}

void getHostsFromIface(pcpp::PcapLiveDevice *dev)
{
    auto addrs = dev->getAddresses();
    for (auto &&i : addrs) {
        if (!i.addr) {
            continue;
        }
        if (i.addr->sa_family == AF_INET) {
            auto adrcvt = pcpp::sockaddr2in_addr(i.addr);
            if (!adrcvt) {
                std::cerr << "couldn't parse IPv4 address on device" << std::endl;
                continue;
            }
            auto nmcvt = pcpp::sockaddr2in_addr(i.netmask);
            if (!nmcvt) {
                std::cerr << "couldn't parse IPv4 netmask address on device" << std::endl;
                continue;
            }
            hostIPv4.emplace_back(pktvisor::IPv4subnet(pcpp::IPv4Address(adrcvt), pcpp::IPv4Address(nmcvt)));
        } else if (i.addr->sa_family == AF_INET6) {
            auto adrcvt = pcpp::sockaddr2in6_addr(i.addr);
            if (!adrcvt) {
                std::cerr << "couldn't parse IPv6 address on device" << std::endl;
                continue;
            }
            auto nmcvt = pcpp::sockaddr2in6_addr(i.netmask);
            if (!nmcvt) {
                std::cerr << "couldn't parse IPv4 netmask address on device" << std::endl;
                continue;
            }
            hostIPv6.emplace_back(pktvisor::IPv6subnet(pcpp::IPv6Address(adrcvt), pcpp::IPv6Address(nmcvt)));
        }
    }
}


void setupRoutes(httplib::Server &svr)
{

    svr.Get("/api/v1/metrics/app", [](const httplib::Request &req, httplib::Response &res) {
        std::string out;
        try {
            out = metricsManager->getAppMetrics();
            res.set_content(out, "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });
    svr.Get("/api/v1/metrics/rates", [](const httplib::Request &req, httplib::Response &res) {
        std::string out;
        try {
            out = metricsManager->getInstantRates();
            res.set_content(out, "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });
    svr.Get(R"(/api/v1/metrics/bucket/(\d+))", [](const httplib::Request &req, httplib::Response &res) {
        std::string out;
        try {
            uint64_t period(std::stol(req.matches[1]));
            out = metricsManager->getMetrics(period);
            res.set_content(out, "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });
    svr.Get(R"(/api/v1/metrics/window/(\d+))", [](const httplib::Request &req, httplib::Response &res) {
        std::string out;
        try {
            uint64_t period(std::stol(req.matches[1]));
            out = metricsManager->getMetricsMerged(period);
            res.set_content(out, "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });
}

void showHosts() {
    for (auto &i : hostIPv4) {
        std::cerr << "Using IPv4 subnet as HOST: " << i.first.toString() << "/" << i.second.toString() << std::endl;
    }
    for (auto &i : hostIPv6) {
        std::cerr << "Using IPv6 subnet as HOST: " << i.first.toString() << "/" << i.second.toString() << std::endl;
    }
}

int main(int argc, char *argv[])
{
    std::map<std::string, docopt::value> args = docopt::docopt(USAGE,
        {argv + 1, argv + argc},
        true,              // show help if requested
        PKTVISOR_VERSION); // version string

    std::string bpf;
    if (args["-b"]) {
        bpf = args["-b"].asString();
    }

    if (args["-H"]) {
        auto spec = args["-H"].asString();
        try {
            pktvisor::parseHostSpec(spec, hostIPv4, hostIPv6);
        } catch (const std::exception &e) {
            std::cerr << e.what() << std::endl;
            return -1;
        }
    }

    long periods{0};
    if (args["--periods"]) {
        periods = args["--periods"].asLong();
    }

    pktvisor::TcpDnsReassembly tcpDnsReassembly(onGotTcpDnsMessage);
    int result = 0;

    if ((args["TARGET"].asString().rfind(".pcap") != std::string::npos) || (args["TARGET"].asString().rfind(".cap") != std::string::npos)) {
        showHosts();
        try {
            // in pcap mode we simply output a single summary of stats
            metricsManager = std::make_unique<pktvisor::MetricsMgr>(args["--summary"].asBool());
            openPcap(args["TARGET"].asString(), tcpDnsReassembly, bpf);
            std::cout << metricsManager->getMetricsMerged(periods) << std::endl;
        } catch (const std::exception &e) {
            std::cerr << e.what() << std::endl;
            return -1;
        }
    } else {
        metricsManager = std::make_unique<pktvisor::MetricsMgr>(false, periods);
        pcpp::PcapLiveDevice *dev(nullptr);
        // extract pcap live device by interface name or IP address
        pcpp::IPv4Address interfaceIP4(args["TARGET"].asString());
        pcpp::IPv6Address interfaceIP6(args["TARGET"].asString());
        if (interfaceIP4.isValid() || interfaceIP6.isValid()) {
            if (interfaceIP4.isValid()) {
                dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP4);
            } else {
                dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP6);
            }
            if (dev == NULL) {
                std::cerr << "Couldn't find interface by provided IP: " << args["TARGET"].asString() << std::endl;
                return -1;
            }
        } else {
            dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(args["TARGET"].asString());
            if (dev == NULL) {
                std::cerr << "Couldn't find interface by provided name: " << args["TARGET"].asString() << std::endl;
                return -1;
            }
        }
        httplib::Server svr;
        setupRoutes(svr);
        auto port = args["-p"].asLong();
        std::thread httpThread([&svr, port] {
            svr.listen("localhost", port);
        });
        try {
            std::cout << "Interface " << dev->getName() << std::endl;
            getHostsFromIface(dev);
            showHosts();
            openIface(dev, tcpDnsReassembly, bpf);
        } catch (const std::exception &e) {
            std::cerr << e.what() << std::endl;
            result = -1;
        }
        svr.stop();
        httpThread.join();
    }

    return result;
}
