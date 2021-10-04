/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "PcapInputStream.h"
#include <pcap.h>
#include <timer.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wc99-extensions"
#pragma GCC diagnostic ignored "-Wpedantic"
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <Logger.h>
#include <PacketUtils.h>
#include <PcapFileDevice.h>
#include <SystemUtils.h>
#pragma GCC diagnostic pop
#include <IpUtils.h>
#include <arpa/inet.h>
#include <assert.h>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <sstream>

using namespace std::chrono;

namespace visor::input::pcap {

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

static void _packet_arrives_cb(pcpp::RawPacket *rawPacket, [[maybe_unused]] pcpp::PcapLiveDevice *dev, void *cookie)
{
    auto stream = static_cast<PcapInputStream *>(cookie);
    stream->process_raw_packet(rawPacket);
}

static void _pcap_stats_update(pcpp::IPcapDevice::PcapStats &stats, void *cookie)
{
    // NOTE this is called from a different thread than the packet and tcp callbacks!
    // We could avoid this by retrieving the stats manually ourselves in the same thread
    auto stream = static_cast<PcapInputStream *>(cookie);
    stream->process_pcap_stats(stats);
}

PcapInputStream::PcapInputStream(const std::string &name)
    : visor::InputStream(name)
    , _pcapDevice(nullptr)
    , _tcp_reassembly(_tcp_message_ready_cb,
          this,
          _tcp_connection_start_cb,
          _tcp_connection_end_cb,
          {true, 5, 500, 50})
{
    pcpp::LoggerPP::getInstance().suppressErrors();
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
        // read from pcap file. this is a special case from a command line utility
        assert(config_exists("bpf"));
        _pcapFile = true;
        // note, parse_host_spec should be called manually by now (in CLI)
        _running = true;
        _open_pcap(config_get<std::string>("pcap_file"), config_get<std::string>("bpf"));
        return;
    }

    if (config_exists("debug")) {
        pcpp::LoggerPP::getInstance().setAllModlesToLogLevel(pcpp::LoggerPP::LogLevel::Debug);
    }

    // live capture
    assert(config_exists("iface"));
    if (!config_exists("bpf")) {
        config_set("bpf", "");
    }
    parse_host_spec();
    std::string TARGET(config_get<std::string>("iface"));
    pcpp::IPv4Address interfaceIP4(TARGET);
    pcpp::IPv6Address interfaceIP6(TARGET);

    _cur_pcap_source = PcapInputStream::DefaultPcapSource;

    if (config_exists("pcap_source")) {
        auto req_source = config_get<std::string>("pcap_source");
        if (req_source == "libpcap") {
            _cur_pcap_source = PcapSource::libpcap;
        } else if (req_source == "af_packet") {
#ifndef __linux__
            throw PcapException("af_packet is only available on linux");
#else
            _cur_pcap_source = PcapSource::af_packet;
#endif
        } else {
            throw PcapException("unknown pcap source");
        }
    }

    if (_cur_pcap_source == PcapSource::libpcap) {
        pcpp::PcapLiveDevice *pcapDevice;
        // extract pcap live device by interface name or IP address
        if (interfaceIP4.isValid() || interfaceIP6.isValid()) {
            if (interfaceIP4.isValid()) {
                pcapDevice = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP4);
            } else {
                pcapDevice = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIP6);
            }
            if (pcapDevice == nullptr) {
                throw PcapException("Couldn't find interface by provided IP: " + TARGET);
            }
        } else {
            pcapDevice = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(TARGET);
            if (pcapDevice == nullptr) {
                throw PcapException("Couldn't find interface by provided name: " + TARGET);
            }
        }

        // PcapPlusPlus upstream incompatibility note: this block requires ns1 fork of PcapPlusPlus until upstream
        // makes PcapLiveDevice constructor pubic
        pcap_if_t *interfaceList;
        char errbuf[PCAP_ERRBUF_SIZE];
        int err = pcap_findalldevs(&interfaceList, errbuf);
        if (err < 0) {
            throw PcapException("Error searching for pcap devices: " + std::string(errbuf));
        }

        pcap_if_t *currInterface = interfaceList;
        while (currInterface != NULL) {
            if (currInterface->name != pcapDevice->getName()) {
                currInterface = currInterface->next;
                continue;
            }
            _pcapDevice = std::make_unique<pcpp::PcapLiveDevice>(currInterface, true, true, true);
            break;
        }

        pcap_freealldevs(interfaceList);
        if (_pcapDevice == nullptr) {
            throw PcapException("Couldn't find interface by provided name: " + TARGET);
        }
        // end upstream PcapPlusPlus incompatibility block

        _get_hosts_from_libpcap_iface();
        _open_libpcap_iface(config_get<std::string>("bpf"));
    } else if (_cur_pcap_source == PcapSource::af_packet) {
#ifndef __linux__
        assert(true);
#else
        _open_af_packet_iface(TARGET, config_get<std::string>("bpf"));
#endif
    } else {
        assert(true);
    }

    _running = true;
}

void PcapInputStream::stop()
{
    if (!_running) {
        return;
    }

    if (!_pcapFile && _pcapDevice) {
        // stop capturing and close the live device
        _pcapDevice->stopCapture();
        _pcapDevice->close();
    }

#ifdef __linux__
    if (_af_device) {
        _af_device->stop_capture();
    }
#endif

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

void PcapInputStream::process_pcap_stats(const pcpp::IPcapDevice::PcapStats &stats)
{
    pcap_stats_signal(stats);
}

void PcapInputStream::process_raw_packet(pcpp::RawPacket *rawPacket)
{

    pcpp::ProtocolType l3(pcpp::UnknownProtocol), l4(pcpp::UnknownProtocol);
    pcpp::Packet packet(rawPacket, pcpp::TCP | pcpp::UDP);
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
            if (IP4layer->getDstIPv4Address().matchSubnet(i.address, i.mask)) {
                dir = PacketDirection::toHost;
                break;
            } else if (IP4layer->getSrcIPv4Address().matchSubnet(i.address, i.mask)) {
                dir = PacketDirection::fromHost;
                break;
            }
        }
    } else if (IP6layer) {
        for (auto &i : _hostIPv6) {
            if (IP6layer->getDstIPv6Address().matchSubnet(i.address, i.mask)) {
                dir = PacketDirection::toHost;
                break;
            } else if (IP6layer->getSrcIPv6Address().matchSubnet(i.address, i.mask)) {
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
        auto result = _tcp_reassembly.reassemblePacket(packet);
        switch (result) {
        case pcpp::TcpReassembly::Error_PacketDoesNotMatchFlow:
        case pcpp::TcpReassembly::NonTcpPacket:
        case pcpp::TcpReassembly::NonIpPacket:
            tcp_reassembly_error_signal(packet, dir, l3, rawPacket->getPacketTimeStamp());
        case pcpp::TcpReassembly::TcpMessageHandled:
        case pcpp::TcpReassembly::OutOfOrderTcpMessageBuffered:
        case pcpp::TcpReassembly::FIN_RSTWithNoData:
        case pcpp::TcpReassembly::Ignore_PacketWithNoData:
        case pcpp::TcpReassembly::Ignore_PacketOfClosedFlow:
        case pcpp::TcpReassembly::Ignore_Retransimission:
            break;
        }
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
    if (!reader->open()) {
        throw PcapException("Cannot open pcap/pcapng file");
    }

    // set BPF filter if set by the user
    if (bpfFilter != "") {
        if (!reader->setFilter(bpfFilter))
            throw PcapException("Cannot set BPF filter to pcap file");
    }

    pcpp::RawPacket rawPacket;
    timespec end_tstamp;

    // setup initial timestamp from first packet to initiate bucketing
    if (reader->getNextPacket(rawPacket)) {
        start_tstamp_signal(rawPacket.getPacketTimeStamp());
        process_raw_packet(&rawPacket);
    }

    int packetCount = 1, lastCount = 0;
    timer t(100ms);
    auto t0 = t.set_interval(1s, [&packetCount, &lastCount]() {
        std::cerr << "processed " << packetCount << " packets (" << lastCount << "/s)\n";
        lastCount = 0;
    });
    while (_running && reader->getNextPacket(rawPacket)) {
        process_raw_packet(&rawPacket);
        packetCount++;
        lastCount++;
        end_tstamp = rawPacket.getPacketTimeStamp();
    }
    end_tstamp_signal(end_tstamp);
    t0->cancel();
    std::cerr << "processed " << packetCount << " packets\n";

    // after all packets have been read - close the connections which are still opened
    _tcp_reassembly.closeAllConnections();

    // close the reader and free its memory
    reader->close();
    delete reader;
}

#ifdef __linux__
void PcapInputStream::_open_af_packet_iface(const std::string &iface, const std::string &bpfFilter)
{

    _af_device = std::make_unique<AFPacket>(this, _packet_arrives_cb, bpfFilter, iface);
    _af_device->start_capture();
}
#endif

void PcapInputStream::_open_libpcap_iface(const std::string &bpfFilter)
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
    config.packetBufferTimeoutMs = 10;
    /*
     * @param[in] snapshotLength Snapshot length for capturing packets. Default value is 0 which means use the default value.
     * A snapshot length of 262144 should be big enough for maximum-size Linux loopback packets (65549) and some USB packets
     * captured with USBPcap (> 131072, < 262144). A snapshot length of 65535 should be sufficient, on most if not all networks,
     * to capture all the data available from the packet.
     */
    config.snapshotLength = 1000;

    // try to open device
    if (!_pcapDevice->open(config)) {
        throw PcapException("Cannot open interface for packet capture");
    }

    // set BPF filter if set by the user
    if (bpfFilter != "" && !_pcapDevice->setFilter(bpfFilter)) {
        throw PcapException("Cannot set BPF filter to interface");
    }

    // start capturing packets with stats info
    if (!_pcapDevice->startCapture(_packet_arrives_cb, this, 1, _pcap_stats_update, this)) {
        throw PcapException("Packet capture failed to start");
    }
}

void PcapInputStream::_get_hosts_from_libpcap_iface()
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

void PcapInputStream::info_json(json &j) const
{
    common_info_json(j);
    json info;
    info["host_ips"] = json::object();
    for (auto &i : _hostIPv4) {
        std::stringstream out;
        int len = 0;
        auto m = i.mask.toInt();
        while (m) {
            len++;
            m >>= 1;
        }
        out << i.address.toString() << '/' << len;
        info["host_ips"]["ipv4"].push_back(out.str());
    }
    for (auto &i : _hostIPv6) {
        std::stringstream out;
        out << i.address.toString() << '/' << static_cast<int>(i.mask);
        info["host_ips"]["ipv6"].push_back(out.str());
    }
    switch (_cur_pcap_source) {
    case PcapSource::unknown:
        info["pcap_source"] = "unknown";
        break;
    case PcapSource::libpcap:
        info["pcap_source"] = "libpcap";
        break;
    case PcapSource::af_packet:
        info["pcap_source"] = "af_packet";
        break;
    }
    j[schema_key()] = info;
}

void PcapInputStream::parse_host_spec()
{
    if (config_exists("host_spec")) {
        parseHostSpec(config_get<std::string>("host_spec"), _hostIPv4, _hostIPv6);
    }
}

}
