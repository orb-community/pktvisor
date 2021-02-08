#include "PcapInputStream.h"
#include "timer.h"
#include <pcap.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <PacketUtils.h>
#include <PcapFileDevice.h>
#include <SystemUtils.h>
#pragma GCC diagnostic pop
#include <Corrade/Utility/Debug.h>
#include <IpUtils.h>
#include <arpa/inet.h>
#include <assert.h>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <sstream>

namespace pktvisor::input::pcap {

// static callbacks for PcapPlusPlus
static void _tcp_message_ready_cb(int8_t side, const pcpp::TcpStreamData &tcpData, void *cookie)
{
    auto stream = static_cast<PcapInputStream *>(cookie);
    stream->tcp_message_ready(side, tcpData);
}

static void _tcp_connection_start_cb(const pcpp::ConnectionData &connectionData, void *cookie)
{
    auto stream = static_cast<PcapInputStream *>(cookie);
    stream->tcp_connection_start(connectionData);
}

static void _tcp_connection_end_cb(const pcpp::ConnectionData &connectionData, pcpp::TcpReassembly::ConnectionEndReason reason, void *cookie)
{
    auto stream = static_cast<PcapInputStream *>(cookie);
    stream->tcp_connection_end(connectionData, reason);
}

static void _packet_arrives_cb(pcpp::RawPacket *rawPacket, pcpp::PcapLiveDevice *dev, void *cookie)
{
    auto stream = static_cast<PcapInputStream *>(cookie);
    stream->process_raw_packet(rawPacket);
}

static void _pcap_stats_update(pcpp::IPcapDevice::PcapStats &stats, void *cookie)
{
    auto stream = static_cast<PcapInputStream *>(cookie);
    // TODO expose this
}

PcapInputStream::PcapInputStream(const std::string &name)
    : pktvisor::InputStream(name)
    , _pcapDevice(nullptr)
    , _tcp_reassembly(_tcp_message_ready_cb,
          this,
          _tcp_connection_start_cb,
          _tcp_connection_end_cb)
{
}

PcapInputStream::~PcapInputStream()
{
}

void PcapInputStream::start()
{

    if (_running) {
        return;
    }

    if (config_exists("pcap_file")) {
        assert(config_exists("bpf"));
        _pcapFile = true;
        // note, parse_host_spec should be called manually by now (in CLI)
        _running = true;
        _open_pcap(config_get<std::string>("pcap_file"), config_get<std::string>("bpf"));
    } else {
        assert(config_exists("iface"));
        assert(config_exists("bpf"));
        parse_host_spec();
        std::string TARGET(config_get<std::string>("iface"));
        pcpp::IPv4Address interfaceIP4(TARGET);
        pcpp::IPv6Address interfaceIP6(TARGET);
        // extract pcap live device by interface name or IP address
        if (interfaceIP4.isValid() || interfaceIP6.isValid()) {
            if (interfaceIP4.isValid()) {
                _pcapDevice = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP4);
            } else {
                _pcapDevice = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP6);
            }
            if (_pcapDevice == nullptr) {
                throw PcapException("Couldn't find interface by provided IP: " + TARGET);
            }
        } else {
            _pcapDevice = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(TARGET);
            if (_pcapDevice == nullptr) {
                throw PcapException("Couldn't find interface by provided name: " + TARGET);
            }
        }
        _get_hosts_from_iface();
        _open_iface(config_get<std::string>("bpf"));
        _running = true;
    }
}

void PcapInputStream::stop()
{
    if (!_running) {
        return;
    }

    if (!_pcapFile) {
        // stop capturing and close the live device
        _pcapDevice->stopCapture();
        _pcapDevice->close();
    }

    // close all connections which are still opened
    _tcp_reassembly.closeAllConnections();

    _running = false;
}

void PcapInputStream::tcp_message_ready(int8_t side, const pcpp::TcpStreamData &tcpData)
{
    tcp_message_ready_signal(side, tcpData);
}

void PcapInputStream::tcp_connection_start(const pcpp::ConnectionData &connectionData)
{
    tcp_connection_start_signal(connectionData);
}

void PcapInputStream::tcp_connection_end(const pcpp::ConnectionData &connectionData, pcpp::TcpReassembly::ConnectionEndReason reason)
{
    tcp_connection_end_signal(connectionData, reason);
}

void PcapInputStream::process_raw_packet(pcpp::RawPacket *rawPacket)
{

    pcpp::ProtocolType l3(pcpp::UnknownProtocol), l4(pcpp::UnknownProtocol);
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
    PacketDirection dir = PacketDirection::unknown;
    auto IP4layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    auto IP6layer = packet.getLayerOfType<pcpp::IPv6Layer>();
    if (IP4layer) {
        for (auto &i : _hostIPv4) {
            if (IP4layer->getDstIpAddress().matchSubnet(i.address, i.mask)) {
                dir = PacketDirection::toHost;
                break;
            } else if (IP4layer->getSrcIpAddress().matchSubnet(i.address, i.mask)) {
                dir = PacketDirection::fromHost;
                break;
            }
        }
    } else if (IP6layer) {
        for (auto &i : _hostIPv6) {
            if (IP6layer->getDstIpAddress().matchSubnet(i.address, i.mask)) {
                dir = PacketDirection::toHost;
                break;
            } else if (IP6layer->getSrcIpAddress().matchSubnet(i.address, i.mask)) {
                dir = PacketDirection::fromHost;
                break;
            }
        }
    }

    // interface to handlers
    packet_signal(packet, dir, l3, l4, rawPacket->getPacketTimeStamp());

    if (l4 == pcpp::UDP) {
        udp_signal(packet, dir, l3, pcpp::hash5Tuple(&packet), rawPacket->getPacketTimeStamp());
    } else if (l4 == pcpp::TCP) {
        _tcp_reassembly.reassemblePacket(rawPacket);
    } else {
        // unsupported layer3 protocol
    }
}

void PcapInputStream::_open_pcap(const std::string &fileName, const std::string &bpfFilter)
{
    assert(_pcapFile);

    // open input file (pcap or pcapng file)
    // NOTE, we are the owner and must free this
    auto reader = pcpp::IFileReaderDevice::getReader(fileName.c_str());

    // try to open the file device
    if (!reader->open())
        throw PcapException("Cannot open pcap/pcapng file");

    // set BPF filter if set by the user
    if (bpfFilter != "") {
        if (!reader->setFilter(bpfFilter))
            throw PcapException("Cannot set BPF filter to pcap file");
    }

    pcpp::RawPacket rawPacket;

    // setup initial timestamp from first packet to initiate bucketing
    if (reader->getNextPacket(rawPacket)) {
        start_tstamp_signal(rawPacket.getPacketTimeStamp());
        process_raw_packet(&rawPacket);
    }

    int packetCount = 1, lastCount = 0;
    pktvisor::Timer t([&packetCount, &lastCount]() {
        std::cerr << "processed " << packetCount << " packets (" << lastCount << "/s)\n";
        lastCount = 0;
    },
        pktvisor::Timer::Interval(1000), false);
    t.start();
    while (_running && reader->getNextPacket(rawPacket)) {
        process_raw_packet(&rawPacket);
        packetCount++;
        lastCount++;
    }
    t.stop();
    std::cerr << "processed " << packetCount << " packets\n";

    // after all packets have been read - close the connections which are still opened
    _tcp_reassembly.closeAllConnections();

    // close the reader and free its memory
    reader->close();
    delete reader;
}

void PcapInputStream::_open_iface(const std::string &bpfFilter)
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
    if (!_pcapDevice->open(config)) {
        throw PcapException("Cannot open interface for packing capture");
    }

    // set BPF filter if set by the user
    if (bpfFilter != "" && !_pcapDevice->setFilter(bpfFilter)) {
        throw PcapException("Cannot set BPF filter to interface");
    }

    // start capturing packets with stats info
    if (!_pcapDevice->startCapture(_packet_arrives_cb, this, 1, _pcap_stats_update, this)) {
        throw PcapException("Cannot a start packet capture");
    }
}

void PcapInputStream::_get_hosts_from_iface()
{
    auto addrs = _pcapDevice->getAddresses();
    for (auto i : addrs) {
        if (!i.addr) {
            continue;
        }
        if (i.addr->sa_family == AF_INET) {
            auto adrcvt = pcpp::internal::sockaddr2in_addr(i.addr);
            if (!adrcvt) {
                throw PcapException("couldn't parse IPv4 address on device");
            }
            auto nmcvt = pcpp::internal::sockaddr2in_addr(i.netmask);
            if (!nmcvt) {
                throw PcapException("couldn't parse IPv4 netmask address on device");
            }
            _hostIPv4.emplace_back(IPv4subnet(pcpp::IPv4Address(pcpp::internal::in_addr2int(*adrcvt)), pcpp::IPv4Address(pcpp::internal::in_addr2int(*nmcvt))));
        } else if (i.addr->sa_family == AF_INET6) {
            char buf1[INET6_ADDRSTRLEN];
            pcpp::internal::sockaddr2string(i.addr, buf1);
            auto nmcvt = pcpp::internal::sockaddr2in6_addr(i.netmask);
            if (!nmcvt) {
                throw PcapException("couldn't parse IPv4 netmask address on device");
            }
            uint8_t len = 0;
            for (int i = 0; i < 16; i++) {
                while (nmcvt->s6_addr[i]) {
                    len++;
                    nmcvt->s6_addr[i] >>= 1;
                }
            }
            _hostIPv6.emplace_back(IPv6subnet(pcpp::IPv6Address(buf1), len));
        }
    }
}

json PcapInputStream::info_json() const
{
    json result;
    for (auto &i : _hostIPv4) {
        std::stringstream out;
        int len = 0;
        auto m = i.mask.toInt();
        while (m) {
            len++;
            m >>= 1;
        }
        out << i.address.toString() << '/' << len;
        result["host_ips"]["ipv4"].push_back(out.str());
    }
    for (auto &i : _hostIPv6) {
        std::stringstream out;
        out << i.address.toString() << '/' << static_cast<int>(i.mask);
        result["host_ips"]["ipv6"].push_back(out.str());
    }
    return result;
}

void PcapInputStream::parse_host_spec()
{
    if (config_exists("host_spec")) {
        parseHostSpec(config_get<std::string>("host_spec"), _hostIPv4, _hostIPv6);
    }
}

}