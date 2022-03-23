/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "InputStream.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#include <IpAddress.h>
#include <PcapLiveDeviceList.h>
#include <TcpReassembly.h>
#include <UdpLayer.h>
#pragma GCC diagnostic pop
#include "utils.h"
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>
#ifdef __linux__
#include "afpacket.h"
#endif

namespace visor::input::pcap {

enum class PcapSource {
    unknown,
    libpcap,
    af_packet,
    mock
};

enum class PacketDirection {
    toHost,
    fromHost,
    unknown
};

class PcapInputStream : public visor::InputStream
{

private:
    static const PcapSource DefaultPcapSource = PcapSource::libpcap;

    IPv4subnetList _hostIPv4;
    IPv6subnetList _hostIPv6;

    PcapSource _cur_pcap_source{PcapSource::unknown};

    // libpcap source
    std::unique_ptr<pcpp::PcapLiveDevice> _pcapDevice;
    bool _pcapFile = false;

    // mock source
    std::unique_ptr<std::thread> _mock_generator_thread;

#ifdef __linux__
    // af_packet source
    std::unique_ptr<AFPacket> _af_device;
#endif

    pcpp::TcpReassembly _tcp_reassembly;

protected:
    void _open_pcap(const std::string &fileName, const std::string &bpfFilter);
    void _open_libpcap_iface(const std::string &bpfFilter = "");
    void _get_hosts_from_libpcap_iface();
    void _generate_mock_traffic();
    std::string _get_interface_list() const;

#ifdef __linux__
    void _open_af_packet_iface(const std::string &iface, const std::string &bpfFilter);
#endif

public:
    PcapInputStream(const std::string &name);
    ~PcapInputStream();

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "pcap";
    }
    void start() override;
    void stop() override;
    void info_json(json &j) const override;
    size_t consumer_count() const override
    {
        return attached_policies.slot_count() + packet_signal.slot_count() + udp_signal.slot_count() + start_tstamp_signal.slot_count() + tcp_message_ready_signal.slot_count() + tcp_connection_start_signal.slot_count() + tcp_connection_end_signal.slot_count() + tcp_reassembly_error_signal.slot_count() + pcap_stats_signal.slot_count();
    }

    // utilities
    void parse_host_spec();

    // public methods that can be called from a static callback method via cookie, required by PcapPlusPlus
    void process_raw_packet(pcpp::RawPacket *rawPacket);
    void process_pcap_stats(const pcpp::IPcapDevice::PcapStats &stats);
    void tcp_message_ready(int8_t side, const pcpp::TcpStreamData &tcpData);
    void tcp_connection_start(const pcpp::ConnectionData &connectionData);
    void tcp_connection_end(const pcpp::ConnectionData &connectionData, pcpp::TcpReassembly::ConnectionEndReason reason);

    // handler functionality
    // IF THIS changes, see consumer_count()
    // note: these are mutable because consumer_count() calls slot_count() which is not const (unclear if it could/should be)
    mutable sigslot::signal<pcpp::Packet &, PacketDirection, pcpp::ProtocolType, pcpp::ProtocolType, timespec> packet_signal;
    mutable sigslot::signal<pcpp::Packet &, PacketDirection, pcpp::ProtocolType, uint32_t, timespec> udp_signal;
    mutable sigslot::signal<timespec> start_tstamp_signal;
    mutable sigslot::signal<timespec> end_tstamp_signal;
    mutable sigslot::signal<int8_t, const pcpp::TcpStreamData &> tcp_message_ready_signal;
    mutable sigslot::signal<const pcpp::ConnectionData &> tcp_connection_start_signal;
    mutable sigslot::signal<const pcpp::ConnectionData &, pcpp::TcpReassembly::ConnectionEndReason> tcp_connection_end_signal;
    mutable sigslot::signal<pcpp::Packet &, PacketDirection, pcpp::ProtocolType, timespec> tcp_reassembly_error_signal;
    mutable sigslot::signal<const pcpp::IPcapDevice::PcapStats &> pcap_stats_signal;
};

}
