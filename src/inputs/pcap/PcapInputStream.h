#ifndef VIZERD_PCAPINPUTSTREAM_H
#define VIZERD_PCAPINPUTSTREAM_H

#include "InputStream.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#include <IpAddress.h>
#include <PcapLiveDeviceList.h>
#include <TcpReassembly.h>
#include <UdpLayer.h>
#pragma GCC diagnostic pop
#include "utils.h"
#include <exception>
#include <functional>
#include <memory>
#include <sigslot/signal.hpp>
#include <unordered_map>
#include <vector>

namespace vizer::input::pcap {

enum class PacketDirection {
    toHost,
    fromHost,
    unknown
};

class PcapException : public std::runtime_error
{
public:
    PcapException(const char *msg)
        : std::runtime_error(msg)
    {
    }
    PcapException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

class PcapInputStream : public vizer::InputStream
{

private:
    IPv4subnetList _hostIPv4;
    IPv6subnetList _hostIPv6;

    pcpp::PcapLiveDevice *_pcapDevice = nullptr;
    bool _pcapFile = false;

    pcpp::TcpReassembly _tcp_reassembly;

protected:
    void _open_pcap(const std::string &fileName, const std::string &bpfFilter = "");
    void _open_iface(const std::string &bpfFilter = "");
    void _get_hosts_from_iface();

public:
    PcapInputStream(const std::string &name);
    ~PcapInputStream();

    // vizer::AbstractModule
    void start() override;
    void stop() override;
    json info_json() const override;
    size_t consumer_count() override
    {
        return packet_signal.slot_count() + udp_signal.slot_count() + start_tstamp_signal.slot_count() + tcp_message_ready_signal.slot_count() + tcp_connection_start_signal.slot_count() + tcp_connection_end_signal.slot_count();
    }

    // utilities
    void parse_host_spec();

    // public methods that can be called from a static callback method via cookie, required by PcapPlusPlus
    void process_raw_packet(pcpp::RawPacket *rawPacket);
    void tcp_message_ready(int8_t side, const pcpp::TcpStreamData &tcpData);
    void tcp_connection_start(const pcpp::ConnectionData &connectionData);
    void tcp_connection_end(const pcpp::ConnectionData &connectionData, pcpp::TcpReassembly::ConnectionEndReason reason);

    // handler functionality
    // IF THIS changes, see consumer_count()
    sigslot::signal<pcpp::Packet &, PacketDirection, pcpp::ProtocolType, pcpp::ProtocolType, timespec> packet_signal;
    sigslot::signal<pcpp::Packet &, PacketDirection, pcpp::ProtocolType, uint32_t, timespec> udp_signal;
    sigslot::signal<timespec> start_tstamp_signal;
    sigslot::signal<int8_t, const pcpp::TcpStreamData &> tcp_message_ready_signal;
    sigslot::signal<const pcpp::ConnectionData &> tcp_connection_start_signal;
    sigslot::signal<const pcpp::ConnectionData &, pcpp::TcpReassembly::ConnectionEndReason> tcp_connection_end_signal;
};

}

#endif //VIZERD_PCAPINPUTSTREAM_H
