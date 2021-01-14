#include "PcapInputStream.h"
#include "timer.h"
#include <pcap.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <PacketUtils.h>
#include <PcapFileDevice.h>
#include <SystemUtils.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <IpUtils.h>
#include <cstdint>
#include <cstring>
#include <assert.h>
#include <Corrade/Utility/Debug.h>

namespace pktvisor {
namespace input {

PcapInputStream::PcapInputStream(const std::string &name)
    : pktvisor::InputStream(name), _pcapDevice(nullptr)
{
    !Corrade::Utility::Debug{} << "create";

    _tcpReassembly = std::make_unique<TcpMsgReassembly>([this](Direction dir, pcpp::ProtocolType l3, uint32_t flowKey, timespec stamp) {
        onGotMessage(dir, l3, pcpp::TCP, flowKey, stamp);
    });

}

PcapInputStream::~PcapInputStream() {
    !Corrade::Utility::Debug{} << "destroy";
}

void PcapInputStream::start()
{

    if (_running) {
        return;
    }

    !Corrade::Utility::Debug{}  << "start";

    // extract pcap live device by interface name or IP address
    std::string TARGET(std::get<std::string>(get_config("iface")));
    pcpp::IPv4Address interfaceIP4(TARGET);
    pcpp::IPv6Address interfaceIP6(TARGET);
    if (interfaceIP4.isValid() || interfaceIP6.isValid()) {
        if (interfaceIP4.isValid()) {
            _pcapDevice = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP4);
        } else {
            _pcapDevice = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP6);
        }
        if (_pcapDevice == nullptr) {
            throw std::runtime_error("Couldn't find interface by provided IP: " + TARGET);
        }
    } else {
        _pcapDevice = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(TARGET);
        if (_pcapDevice == nullptr) {
            throw std::runtime_error("Couldn't find interface by provided name: " + TARGET);
        }
    }
//        std::cerr << "Interface " << dev->getName() << std::endl;
        getHostsFromIface();
//        showHosts();
        openIface(std::get<std::string>(get_config("bpf")));
        _running = true;
}

void PcapInputStream::stop()
{
    if (!_running) {
        return;
    }

    !Corrade::Utility::Debug{}  << "stop";

    // stop capturing and close the live device
    _pcapDevice->stopCapture();
    _pcapDevice->close();

    // close all connections which are still opened
    _tcpReassembly->getTcpReassembly()->closeAllConnections();

    _running = false;
}

// got a full DNS wire message. called from all l3 and l4.
void PcapInputStream::onGotMessage(Direction dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowKey, timespec stamp)
{
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


/**
 * Called for live and pcap
 */
void PcapInputStream::processRawPacket(pcpp::RawPacket *rawPacket)
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


    // interface to handlers
    // TODO NETWORK

    if (l4 == pcpp::UDP) {

        pcpp::UdpLayer *udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
        assert(udpLayer);
        _udp_signal(*udpLayer);
        /*
        // sync
        for (auto&& i : _udp_consumers) {
            if (i.second.port == 0 || i.second.port == ntohs(udpLayer->getUdpHeader()->portDst) || i.second.port == ntohs(udpLayer->getUdpHeader()->portSrc)) {
                i.second.callback(*udpLayer);
            }
        }

        // FIXME async
        bool detached = false;
        std::shared_ptr<pcpp::UdpLayer> udpLayerCopy;
        for (auto&& i : _udp_consumers_async) {
            if (i.second.port == 0 || i.second.port == ntohs(udpLayer->getUdpHeader()->portDst) || i.second.port == ntohs(udpLayer->getUdpHeader()->portSrc)) {
                if (!detached) {
                    packet.detachLayer(udpLayer);
                    udpLayerCopy.reset(udpLayer);
                    detached = true;
                }
                i.second.queue->enqueue(udpLayerCopy);
            }
        }*/

    } else if (l4 == pcpp::TCP) {
        // get a pointer to the TCP reassembly instance and feed the packet arrived to it
        _tcpReassembly->getTcpReassembly()->reassemblePacket(rawPacket);
    } else {
        // unsupported layer3 protocol
    }

}

/*void PcapInputStream::register_packet_consumer(const std::string &name, PcapInputStream::PacketCallback cb) {
    auto lock = _lock_consumers();
    _packet_consumers.emplace(std::make_pair(name, std::move(cb)));
}

void PcapInputStream::deregister_packet_consumer(const std::string &name) {
    auto lock = _lock_consumers();
    _packet_consumers.erase(name);
}

void PcapInputStream::register_udp_consumer(const std::string &name, uint16_t port, PcapInputStream::UdpLayerCallback cb)
{
    auto lock = _lock_consumers();
    UdpConsumer consumer(port, std::move(cb));
    _udp_consumers.emplace(std::make_pair(name, std::move(consumer)));
}

PcapInputStream::ConcurrentUdpQueue* PcapInputStream::register_udp_consumer_async(const std::string &name, uint16_t port)
{
    auto lock = _lock_consumers();
    // FIXME
    UdpConsumerAsync consumer(port);
    _udp_consumers_async.emplace(std::make_pair(name, std::move(consumer)));
    return _udp_consumers_async.at(name).queue.get();
}*/

void PcapInputStream::openPcap(std::string fileName, std::string bpfFilter)
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

    // TODO
//    pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &dC);

    // run in a loop that reads one packet from the file in each iteration and feeds it to the TCP reassembly instance
    pcpp::RawPacket rawPacket;
    // setup initial timestamp from first packet to initiate bucketing
    if (reader->getNextPacket(rawPacket)) {
        // TODO interface to handler
        //        metricsManager->setInitialShiftTS(&rawPacket);
        processRawPacket(&rawPacket);
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
//    while (reader->getNextPacket(rawPacket) && !dC.second) {
    while (reader->getNextPacket(rawPacket)) {
        packetCount++;
        lastCount++;
        processRawPacket(&rawPacket);
    }
    t.stop();

    // after all packets have been read - close the connections which are still opened
    _tcpReassembly->getTcpReassembly()->closeAllConnections();

    // close the reader and free its memory
    reader->close();
    delete reader;
}

/**
 * packet capture callback - called whenever a packet arrives on the live device (in live device capturing mode)
 */
static void onLivePacketArrives(pcpp::RawPacket *rawPacket, pcpp::PcapLiveDevice *dev, void *cookie)
{
    Corrade::Utility::Debug{} << "packet arrives";
    PcapInputStream *dC = (PcapInputStream *)cookie;
    dC->processRawPacket(rawPacket);
}

void PcapInputStream::openIface(std::string bpfFilter)
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
    if (!_pcapDevice->open(config))
        throw std::runtime_error("Cannot open interface for packing capture");

    // set BPF filter if set by the user
    if (bpfFilter != "") {
        if (!_pcapDevice->setFilter(bpfFilter))
            throw std::runtime_error("Cannot set BPF filter to interface");
        //        std::cerr << "BPF: " << bpfFilter << std::endl;
    }

    //printf("Starting packet capture on '%s'...\n", dev->getName());

    // TODO
    //    metricsManager->setInitialShiftTS();


    // start capturing packets
    // TODO Pcap statistics on dropped packets OnStatsUpdateCallback
    if (!_pcapDevice->startCapture(onLivePacketArrives, this)) {
        throw std::runtime_error("Cannot a start packet capture");
    }
}

void PcapInputStream::getHostsFromIface()
{
    auto addrs = _pcapDevice->getAddresses();
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

TcpSessionData::TcpSessionData(
    malformed_data_cb malformed_data_handler,
    got_data_cb got_data_handler)
    : _malformed_data{std::move(malformed_data_handler)}
    , _got_msg{std::move(got_data_handler)}
{
}

// accumulate data and try to extract DNS messages
void TcpSessionData::receive_data(const char data[], size_t len)
{
    const size_t MIN_DNS_QUERY_SIZE = 17;
    const size_t MAX_DNS_QUERY_SIZE = 512;

    _buffer.append(data, len);

    for (;;) {
        std::uint16_t size;

        if (_buffer.size() < sizeof(size))
            break;

        // size is in network byte order.
        size = static_cast<unsigned char>(_buffer[1]) | static_cast<unsigned char>(_buffer[0]) << 8;

        if (size < MIN_DNS_QUERY_SIZE || size > MAX_DNS_QUERY_SIZE) {
            _malformed_data();
            break;
        }

        if (_buffer.size() >= sizeof(size) + size) {
            auto data = std::make_unique<char[]>(size);
            std::memcpy(data.get(), _buffer.data() + sizeof(size), size);
            _buffer.erase(0, sizeof(size) + size);
            _got_msg(std::move(data), size);
        } else {
            // Nope, we need more data.
            break;
        }
    }
}


static void tcpReassemblyConnectionStartCallback(const pcpp::ConnectionData& connectionData, void *userCookie)
{

    // only track DNS connections
    /*
    if (!pktvisor::DnsLayer::isDnsPort(connectionData.srcPort) && !pktvisor::DnsLayer::isDnsPort(connectionData.dstPort)) {
        return;
    }
     */

    TcpReassemblyMgr *reassemblyMgr = (TcpReassemblyMgr *)userCookie;
    auto connMgr = reassemblyMgr->connMgr;
    // get a pointer to the connection manager

    // look for the connection in the connection manager
    auto iter = connMgr.find(connectionData.flowKey);

    // assuming it's a new connection
    if (iter == connMgr.end()) {
        // add it to the connection manager
        connMgr.insert(std::make_pair(connectionData.flowKey, TcpReassemblyData(connectionData.srcIP.getType() == pcpp::IPAddress::IPv4AddressType)));
    }
}

static void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData& connectionData, pcpp::TcpReassembly::ConnectionEndReason reason, void *userCookie)
{
    TcpReassemblyMgr *reassemblyMgr = (TcpReassemblyMgr *)userCookie;
    auto connMgr = reassemblyMgr->connMgr;
    // get a pointer to the connection manager

    // find the connection in the connection manager by the flow key
    auto iter = connMgr.find(connectionData.flowKey);

    // connection wasn't found, we didn't track
    if (iter == connMgr.end())
        return;

    // remove the connection from the connection manager
    connMgr.erase(iter);
}

TcpMsgReassembly::TcpMsgReassembly(TcpReassemblyMgr::process_msg_cb process_msg_handler)
    : _reassemblyMgr()
{

    auto tcpReassemblyMsgReadyCallback = [](int8_t sideIndex, const pcpp::TcpStreamData &tcpData, void *userCookie) {
        // extract the connection manager from the user cookie
        TcpReassemblyMgr *reassemblyMgr = (TcpReassemblyMgr *)userCookie;
        auto connMgr = reassemblyMgr->connMgr;
        auto flowKey = tcpData.getConnectionData().flowKey;

        // check if this flow already appears in the connection manager. If not add it
        auto iter = connMgr.find(flowKey);

        // if not tracking connection, and it's DNS, then start tracking.
        if (iter == connMgr.end() /*&& (pktvisor::DnsLayer::isDnsPort(tcpData.getConnectionData().srcPort) || pktvisor::DnsLayer::isDnsPort(tcpData.getConnectionData().dstPort))*/) {
            connMgr.insert(std::make_pair(flowKey, TcpReassemblyData(tcpData.getConnectionData().srcIP.getType() == pcpp::IPAddress::IPv4AddressType)));
            iter = connMgr.find(tcpData.getConnectionData().flowKey);
        }
        else {
            // not tracking
            return;
        }

        int side(0);

        // if this messages comes on a different side than previous message seen on this connection
        if (sideIndex != iter->second.curSide) {
            // count number of message in each side
//            iter->second.numOfMessagesFromSide[sideIndex]++;

            // set side index as the current active side
            iter->second.curSide = sideIndex;
        }

        // count number of packets and bytes in each side of the connection
//        iter->second.numOfDataPackets[sideIndex]++;
//        iter->second.bytesFromSide[sideIndex] += (int)tcpData.getDataLength();

        pcpp::ProtocolType l3Type(iter->second.l3Type);

        auto malformed_data = []() {
            //            std::cerr << "malformed\n";
        };
        auto got_dns_message = [reassemblyMgr, sideIndex, l3Type, flowKey, tcpData](std::unique_ptr<const char[]> data,
                                                                                    size_t size) {
            pcpp::Packet dnsRequest;
            // TODO fixme
            //pktvisor::DnsLayer dnsLayer((uint8_t *)data.get(), size, nullptr, &dnsRequest);
            auto dir = (sideIndex == 0) ? fromHost : toHost;
            timespec eT{0,0};
            TIMEVAL_TO_TIMESPEC(&tcpData.getConnectionData().endTime, &eT)
            reassemblyMgr->process_msg_handler(dir, l3Type, flowKey, eT);
        };
        if (!iter->second._sessionData[side].get()) {
            iter->second._sessionData[side] = std::make_shared<TcpSessionData>(malformed_data, got_dns_message);
        }
        iter->second._sessionData[side]->receive_data((char *)tcpData.getData(), tcpData.getDataLength());
    };

    _reassemblyMgr.process_msg_handler = process_msg_handler;
    _tcpReassembly = std::make_shared<pcpp::TcpReassembly>(
        tcpReassemblyMsgReadyCallback,
        &_reassemblyMgr,
        tcpReassemblyConnectionStartCallback,
        tcpReassemblyConnectionEndCallback);
}

}
}