#include "PcapStreamInput.h"
#include "timer.h"
#include <pcap.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <PacketUtils.h>
#include <PcapFileDevice.h>
#include <SystemUtils.h>
#include <UdpLayer.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <IpUtils.h>

namespace pktvisor {
namespace input {

PcapStreamInput::maybeError PcapStreamInput::start()
{
    pcpp::PcapLiveDevice *dev(nullptr);

    // extract pcap live device by interface name or IP address
    // TODO
    std::string TARGET;
    pcpp::IPv4Address interfaceIP4(TARGET);
    pcpp::IPv6Address interfaceIP6(TARGET);
    if (interfaceIP4.isValid() || interfaceIP6.isValid()) {
        if (interfaceIP4.isValid()) {
            dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP4);
        } else {
            dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP6);
        }
        if (dev == NULL) {
            std::string err("Couldn't find interface by provided IP: " + TARGET);
            return {false, err};
        }
    } else {
        dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(TARGET);
        if (dev == NULL) {
            std::string err("Couldn't find interface by provided name: " + TARGET);
            return {false, err};
        }
    }
    return {true, ""};
}

void PcapStreamInput::stop()
{
}

// got a full DNS wire message. called from all l3 and l4.
void PcapStreamInput::onGotDnsMessage(pktvisor::DnsLayer *dnsLayer, Direction dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowKey, timespec stamp)
{
    assert(dnsLayer != nullptr);
    // TODO interface to handler

    /*    metricsManager->newDNSPacket(dnsLayer, dir, l3, l4);
    if (dnsLayer->getDnsHeader()->queryOrResponse == pktvisor::response) {
        auto xact = dnsQueryPairManager.maybeEndDnsTransaction(flowKey, dnsLayer->getDnsHeader()->transactionID, stamp);
        if (xact.first) {
            metricsManager->newDNSXact(dnsLayer, dir, xact.second);
        }
    } else {
        dnsQueryPairManager.startDnsTransaction(flowKey, dnsLayer->getDnsHeader()->transactionID, stamp);
    }*/
};

// called only for TCP, both IPv4 and 6
void PcapStreamInput::onGotTcpDnsMessage(pktvisor::DnsLayer *dnsLayer, Direction dir, pcpp::ProtocolType l3, uint32_t flowKey, timespec stamp)
{
    onGotDnsMessage(dnsLayer, dir, l3, pcpp::TCP, flowKey, stamp);
}

/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
void PcapStreamInput::onApplicationInterrupted(void *cookie)
{
    //    std::cerr << "\nstopping..." << std::endl;
    devCookie *dC = (devCookie *)cookie;
    dC->second = true;
}

/**
 * Called for live and pcap
 */
void PcapStreamInput::processRawPacket(pcpp::RawPacket *rawPacket, TcpDnsReassembly *tcpReassembly)
{

    pcpp::ProtocolType l3(pcpp::UnknownProtocol), l4(pcpp::UnknownProtocol);
    // we will parse application layer ourselves
    pcpp::Packet packet(rawPacket, pcpp::OsiModelTransportLayer);
    if (packet.isPacketOfType(pcpp::IPv4)) {
        l3 = pcpp::IPv4;
    } else if (packet.isPacketOfType(pcpp::IPv6)) {
        l3 = pcpp::IPv6;
    }
    if (packet.isPacketOfType(pcpp::UDP)) {
        l4 = pcpp::UDP;
    } else if (packet.isPacketOfType(pcpp::TCP)) {
        l4 = pcpp::TCP;
    }
    // determine packet direction by matching source/dest ips
    // note the direction may be indeterminate!
    Direction dir = unknown;
    auto IP4layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    auto IP6layer = packet.getLayerOfType<pcpp::IPv6Layer>();
    if (IP4layer) {
        for (auto &i : hostIPv4) {
            if (IP4layer->getDstIpAddress().matchSubnet(i.address, i.mask)) {
                dir = toHost;
                break;
            } else if (IP4layer->getSrcIpAddress().matchSubnet(i.address, i.mask)) {
                dir = fromHost;
                break;
            }
        }
    } else if (IP6layer) {
        for (auto &i : hostIPv6) {
            if (IP6layer->getDstIpAddress().matchSubnet(i.address, i.mask)) {
                dir = toHost;
                break;
            } else if (IP6layer->getSrcIpAddress().matchSubnet(i.address, i.mask)) {
                dir = fromHost;
                break;
            }
        }
    }

    // TODO interface to handler

    /*    metricsManager->newPacket(packet, dnsQueryPairManager, l4, dir, l3);
    pcpp::UdpLayer *udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (udpLayer && (pktvisor::DnsLayer::isDnsPort(ntohs(udpLayer->getUdpHeader()->portDst)) || pktvisor::DnsLayer::isDnsPort(ntohs(udpLayer->getUdpHeader()->portSrc)))) {
        pktvisor::DnsLayer dnsLayer = pktvisor::DnsLayer(udpLayer, &packet);
        onGotDnsMessage(&dnsLayer, dir, l3, l4, pcpp::hash5Tuple(&packet), rawPacket->getPacketTimeStamp());
    } else if (packet.isPacketOfType(pcpp::TCP)) {
        // get a pointer to the TCP reassembly instance and feed the packet arrived to it
        // we don't know yet if it's DNS, the reassembly manager figures that out
        tcpReassembly->getTcpReassembly()->reassemblePacket(rawPacket);
    } else {
        // unsupported layer3 protocol
    }*/
}

void PcapStreamInput::openPcap(std::string fileName, TcpDnsReassembly &tcpReassembly, std::string bpfFilter)
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
        // TODO interface to handler
        //        metricsManager->setInitialShiftTS(&rawPacket);
        processRawPacket(&rawPacket, &tcpReassembly);
    }

    int packetCount = 0, lastCount = 0;
    pktvisor::Timer t([&packetCount, &lastCount]() {
        // TODO
        //        std::cerr << "\rprocessed " << packetCount << " packets (" << lastCount << "/s)";
        lastCount = 0;
    },
        pktvisor::Timer::Interval(1000), false);
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
bool PcapStreamInput::onLivePacketArrives(pcpp::RawPacket *rawPacket, pcpp::PcapLiveDevice *dev, void *cookie)
{
    devCookie *dC = (devCookie *)cookie;
    processRawPacket(rawPacket, dC->first);
    // false means don't stop capturing after this callback runs
    // this is controlled by onApplicationInterrupted
    return dC->second;
}

void PcapStreamInput::openIface(pcpp::PcapLiveDevice *dev, TcpDnsReassembly &tcpReassembly, std::string bpfFilter)
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
        //        std::cerr << "BPF: " << bpfFilter << std::endl;
    }

    printf("Starting packet capture on '%s'...\n", dev->getName());

    // register the on app close event to print summary stats on app termination
    devCookie dC = {&tcpReassembly, false};
    pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &dC);

    // TODO
    //    metricsManager->setInitialShiftTS();

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

void PcapStreamInput::getHostsFromIface(pcpp::PcapLiveDevice *dev)
{
    auto addrs = dev->getAddresses();
    for (auto i : addrs) {
        if (!i.addr) {
            continue;
        }
        if (i.addr->sa_family == AF_INET) {
            auto adrcvt = pcpp::internal::sockaddr2in_addr(i.addr);
            if (!adrcvt) {
                // TODO
//                std::cerr << "couldn't parse IPv4 address on device" << std::endl;
                continue;
            }
            auto nmcvt = pcpp::internal::sockaddr2in_addr(i.netmask);
            if (!nmcvt) {
                // TODO
//                std::cerr << "couldn't parse IPv4 netmask address on device" << std::endl;
                continue;
            }
            hostIPv4.emplace_back(IPv4subnet(pcpp::IPv4Address(pcpp::internal::in_addr2int(*adrcvt)), pcpp::IPv4Address(pcpp::internal::in_addr2int(*nmcvt))));
        } else if (i.addr->sa_family == AF_INET6) {
            char buf1[INET6_ADDRSTRLEN];
            pcpp::internal::sockaddr2string(i.addr, buf1);
            auto nmcvt = pcpp::internal::sockaddr2in6_addr(i.netmask);
            if (!nmcvt) {
                // TODO
//                std::cerr << "couldn't parse IPv4 netmask address on device" << std::endl;
                continue;
            }
            uint8_t len = 0;
            for (int i = 0; i < 16; i++) {
                while (nmcvt->s6_addr[i]) {
                    len++;
                    nmcvt->s6_addr[i] >>= 1;
                }
            }
            hostIPv6.emplace_back(IPv6subnet(pcpp::IPv6Address(buf1), len));
        }
    }
}

}
}