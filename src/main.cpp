#include <iostream>

#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <PacketUtils.h>
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>
#include <SystemUtils.h>
#include <UdpLayer.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <IpUtils.h>

#include <cpp-httplib/httplib.h>
#include <docopt/docopt.h>

#include "pcap.h"
#include "config.h"
#include "dns/dns.h"
#include "metrics.h"
#include "pktvisor.h"
#include "querypairmgr.h"
#include "tcpsession.h"
#include "timer.h"
#include "utils.h"

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

static std::unique_ptr<pktvisor::MetricsMgr> metricsManager;
static pktvisor::QueryResponsePairMgr dnsQueryPairManager;

static pktvisor::IPv4subnetList hostIPv4;
static pktvisor::IPv6subnetList hostIPv6;
typedef std::pair<pktvisor::TcpDnsReassembly *, bool> devCookie;

// got a full DNS wire message. called from all l3 and l4.
static void onGotDnsMessage(pktvisor::DnsLayer *dnsLayer, pktvisor::Direction dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowKey, timespec stamp)
{
    assert(dnsLayer != nullptr);
    metricsManager->newDNSPacket(dnsLayer, dir, l3, l4);
    if (dnsLayer->getDnsHeader()->queryOrResponse == pktvisor::response) {
        auto xact = dnsQueryPairManager.maybeEndDnsTransaction(flowKey, dnsLayer->getDnsHeader()->transactionID, stamp);
        if (xact.first) {
            metricsManager->newDNSXact(dnsLayer, dir, xact.second);
        }
    } else {
        dnsQueryPairManager.startDnsTransaction(flowKey, dnsLayer->getDnsHeader()->transactionID, stamp);
    }
};

// called only for TCP, both IPv4 and 6
static void onGotTcpDnsMessage(pktvisor::DnsLayer *dnsLayer, pktvisor::Direction dir, pcpp::ProtocolType l3, uint32_t flowKey, timespec stamp)
{
    onGotDnsMessage(dnsLayer, dir, l3, pcpp::TCP, flowKey, stamp);
}

/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
static void onApplicationInterrupted(void *cookie)
{
    std::cerr << "\nstopping..." << std::endl;
    devCookie *dC = (devCookie *)cookie;
    dC->second = true;
}

/**
 * Called for live and pcap
 */
static void processRawPacket(pcpp::RawPacket *rawPacket, pktvisor::TcpDnsReassembly *tcpReassembly)
{

    pcpp::ProtocolType l3(pcpp::UnknownProtocol), l4(pcpp::UnknownProtocol);
    // we will parse application layer ourselves
    pcpp::Packet packet(rawPacket, pcpp::OsiModelTransportLayer);
    if (packet.isPacketOfType(pcpp::IPv4)) {
        l3 = pcpp::IPv4;
    }
    else if (packet.isPacketOfType(pcpp::IPv6)) {
        l3 = pcpp::IPv6;
    }
    if (packet.isPacketOfType(pcpp::UDP)) {
        l4 = pcpp::UDP;
    }
    else if (packet.isPacketOfType(pcpp::TCP)) {
        l4 = pcpp::TCP;
    }
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
    pcpp::UdpLayer *udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (udpLayer &&
        (pktvisor::DnsLayer::isDnsPort(ntohs(udpLayer->getUdpHeader()->portDst)) ||
            pktvisor::DnsLayer::isDnsPort(ntohs(udpLayer->getUdpHeader()->portSrc)))) {
        pktvisor::DnsLayer dnsLayer = pktvisor::DnsLayer(udpLayer, &packet);
        onGotDnsMessage(&dnsLayer, dir, l3, l4, pcpp::hash5Tuple(&packet), rawPacket->getPacketTimeStamp());
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

    devCookie dC = {&tcpReassembly, false};
    pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &dC);

    // run in a loop that reads one packet from the file in each iteration and feeds it to the TCP reassembly instance
    pcpp::RawPacket rawPacket;
    // setup initial timestamp from first packet to initiate bucketing
    if (reader->getNextPacket(rawPacket)) {
        metricsManager->setInitialShiftTS(&rawPacket);
        processRawPacket(&rawPacket, &tcpReassembly);
    }

    int packetCount = 0, lastCount = 0;
    pktvisor::Timer t([&packetCount, &lastCount]() {
        std::cerr << "\rprocessed " << packetCount << " packets (" << lastCount << "/s)";
        lastCount = 0;
    }, pktvisor::Timer::Interval(1000), false);
    t.start();
    // dC.second answers question "stopping?"
    while (reader->getNextPacket(rawPacket) && !dC.second) {
        packetCount++;
        lastCount++;
        processRawPacket(&rawPacket, &tcpReassembly);
    }
    t.stop();

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
        std::cerr << "BPF: " << bpfFilter << std::endl;
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
    for (auto i : addrs) {
        if (!i.addr) {
            continue;
        }
        if (i.addr->sa_family == AF_INET) {
            auto adrcvt = pcpp::internal::sockaddr2in_addr(i.addr);
            if (!adrcvt) {
                std::cerr << "couldn't parse IPv4 address on device" << std::endl;
                continue;
            }
            auto nmcvt = pcpp::internal::sockaddr2in_addr(i.netmask);
            if (!nmcvt) {
                std::cerr << "couldn't parse IPv4 netmask address on device" << std::endl;
                continue;
            }
            hostIPv4.emplace_back(pktvisor::IPv4subnet(pcpp::IPv4Address(pcpp::internal::in_addr2int(*adrcvt)), pcpp::IPv4Address(pcpp::internal::in_addr2int(*nmcvt))));
        } else if (i.addr->sa_family == AF_INET6) {
            char buf1[INET6_ADDRSTRLEN];
            pcpp::internal::sockaddr2string(i.addr, buf1);
            auto nmcvt = pcpp::internal::sockaddr2in6_addr(i.netmask);
            if (!nmcvt) {
                std::cerr << "couldn't parse IPv4 netmask address on device" << std::endl;
                continue;
            }
            uint8_t len = 0;
            for (int i = 0; i < 16; i++) {
                while (nmcvt->s6_addr[i]) {
                    len++;
                    nmcvt->s6_addr[i] >>= 1;
                }
            }
            hostIPv6.emplace_back(pktvisor::IPv6subnet(pcpp::IPv6Address(buf1), len));
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
        std::cerr << "Using IPv6 subnet as HOST: " << i.first.toString() << "/" << int(i.second) << std::endl;
    }
}

void handleGeo(const docopt::value &city, const docopt::value &asn) {
    if (city) {
        if (!metricsManager->haveGeoCity()) {
            std::cerr << "warning: --geo-city has no effect, lacking compile-time support" << std::endl;
        }
        else {
            metricsManager->setGeoCityDB(city.asString());
        }
    }
    if (asn) {
        if (!metricsManager->haveGeoASN()) {
            std::cerr << "warning: --geo-asn has no effect, lacking compile-time support" << std::endl;
        }
        else {
            metricsManager->setGeoASNDB(asn.asString());
        }
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
    int sampleRate = 100;
    if (args["--max-deep-sample"]) {
        sampleRate = (int)args["--max-deep-sample"].asLong();
        if (sampleRate != 100) {
            std::cerr << "Using maximum deep sample rate: " << sampleRate << "%" << std::endl;
        }
    }

    if ((args["TARGET"].asString().rfind(".pcap") != std::string::npos) || (args["TARGET"].asString().rfind(".cap") != std::string::npos)) {
        showHosts();
        try {
            metricsManager = std::make_unique<pktvisor::MetricsMgr>(args["--summary"].asBool(), 5, sampleRate);
            handleGeo(args["--geo-city"], args["--geo-asn"]);
            openPcap(args["TARGET"].asString(), tcpDnsReassembly, bpf);
            if (args["--summary"].asBool()) {
                // in summary mode we output a single summary of stats
                std::cout << std::endl << metricsManager->getMetrics() << std::endl;
            }
            else {
                // otherwise, merge the max time window available
                std::cout << std::endl << metricsManager->getMetricsMerged(periods) << std::endl;
            }
        } catch (const std::exception &e) {
            std::cerr << e.what() << std::endl;
            return -1;
        }
    } else {
        metricsManager = std::make_unique<pktvisor::MetricsMgr>(false, periods, sampleRate);
        handleGeo(args["--geo-city"], args["--geo-asn"]);
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
        auto host = args["-l"].asString();
        auto port = args["-p"].asLong();
        std::thread httpThread([&svr, host, port] {
            if (!svr.listen(host.c_str(), port)) {
                throw std::runtime_error("unable to listen");
            }
        });
        std::cerr << "Metrics web server listening on " << host << ":" << port << std::endl;
        try {
            std::cerr << "Interface " << dev->getName() << std::endl;
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
