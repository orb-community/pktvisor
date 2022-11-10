/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "InputStream.h"

#ifdef _WIN32
//Required for PcapPlusPlus on Windows
#pragma comment(lib, "iphlpapi.lib")
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#include <IpAddress.h>
#include <PcapLiveDeviceList.h>
#include <TcpReassembly.h>
#include <UdpLayer.h>
#include <algorithm>
#include <spdlog/spdlog.h>
#pragma GCC diagnostic pop
#include "VisorLRUList.h"
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

class TcpSessionData
{
public:
    using got_msg_cb = std::function<void(std::unique_ptr<uint8_t[]> data, size_t size)>;

protected:
    std::string _buffer;
    got_msg_cb _got_msg;
    bool _invalid_data;

public:
    TcpSessionData(
        got_msg_cb got_data_handler)
        : _got_msg{std::move(got_data_handler)}
        , _invalid_data(false)
    {
    }

    virtual ~TcpSessionData()
    {
    }

    // called from pcpp::TcpReassembly callback, matches types
    virtual void receive_tcp_data(const uint8_t *data, size_t len) = 0;
};

struct TcpFlowData {

    std::unique_ptr<TcpSessionData> sessionData[2];
    pcpp::ProtocolType l3Type;
    uint16_t port;

    TcpFlowData(bool isIPv4, uint16_t port)
        : port(port)
    {
        (isIPv4) ? l3Type = pcpp::IPv4 : l3Type = pcpp::IPv6;
    }
};

class PcapInputStream : public visor::InputStream
{

private:
    static constexpr uint8_t TCP_TIMEOUT = 30;
    static constexpr uint8_t MAX_TCP_CLEANUPS = 100;

    static const PcapSource DefaultPcapSource = PcapSource::libpcap;
    LRUList<uint32_t, timeval> _lru_list;
    IPv4subnetList _hostIPv4;
    IPv6subnetList _hostIPv6;
    PacketDirection _packet_dir{PacketDirection::unknown};

    PcapSource _cur_pcap_source{PcapSource::unknown};

    // libpcap source
    std::unique_ptr<pcpp::PcapLiveDevice> _pcapDevice;
    bool _pcapFile = false;

    uint8_t repeat_counter = 0;

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
    std::unique_ptr<InputEventProxy> create_event_proxy(const Configurable &filter) override;

    // utilities
    void parse_host_spec();

    // public methods that can be called from a static callback method via cookie, required by PcapPlusPlus
    void process_raw_packet(pcpp::RawPacket *rawPacket);
    void process_pcap_stats(const pcpp::IPcapDevice::PcapStats &stats);
    void tcp_message_ready(int8_t side, const pcpp::TcpStreamData &tcpData);
    void tcp_connection_start(const pcpp::ConnectionData &connectionData);
    void tcp_connection_end(const pcpp::ConnectionData &connectionData, pcpp::TcpReassembly::ConnectionEndReason reason);
};

class PcapInputEventProxy : public visor::InputEventProxy
{
public:
    // a predicate takes same signature as UdpSignalCB, but returns the value needed for a particular predicate key, i.e. the second half of key in _udp_predicate_signals
    typedef std::function<std::string(pcpp::Packet &, PacketDirection, pcpp::ProtocolType, uint32_t, timespec)> UdpPredicate;
    // signature for udp callback, should be same as non predicate. Signal needs context.
    typedef std::function<void(pcpp::Packet &, PacketDirection, pcpp::ProtocolType, uint32_t, timespec)> UdpSignalCB;

    typedef sigslot::signal<pcpp::Packet &, PacketDirection, pcpp::ProtocolType, uint32_t, timespec> UdpPredicateSignal;

private:
    // key example: dnsonly_rcode0
    std::map<std::string, UdpPredicate> _udp_predicates;
    // key example: dnsonly_rcode3
    std::unordered_map<std::string, UdpPredicateSignal> _udp_predicate_signals;
    // key: <handlerid>
    std::map<std::string, sigslot::connection> _udp_predicate_connections;

    mutable std::shared_mutex _pcap_proxy_mutex;
    std::shared_ptr<spdlog::logger> _logger;

public:
    PcapInputEventProxy(const std::string &name, const Configurable &filter)
        : InputEventProxy(name, filter)
    {
        _logger = spdlog::get("visor");
        assert(_logger);
    }

    ~PcapInputEventProxy() = default;

    size_t consumer_count() const override
    {
        return policy_signal.slot_count() + heartbeat_signal.slot_count() + packet_signal.slot_count() + udp_signal.slot_count() + start_tstamp_signal.slot_count() + tcp_message_ready_signal.slot_count() + tcp_connection_start_signal.slot_count() + tcp_connection_end_signal.slot_count() + tcp_reassembly_error_signal.slot_count() + pcap_stats_signal.slot_count();
    }

    void process_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp)
    {
        packet_signal(payload, dir, l3, l4, stamp);
    }

    void register_udp_predicate_signal(const std::string &schema_key, const std::string &handler_id, const std::string &predicate_key, const std::string &conditional_value, UdpPredicate predicate, UdpSignalCB callback)
    {
        std::unique_lock lock(_pcap_proxy_mutex);
        // if predicate has not been installed yet, install it now
        // note that it is namespaced to each handler so that different handlers can have the same predicate_key
        auto full_predicate_key = schema_key + predicate_key;
        auto predicate_jump_key = full_predicate_key + conditional_value;
        if (_udp_predicates.find(full_predicate_key) == _udp_predicates.end()) {
            _udp_predicates[full_predicate_key] = predicate;
        }
        // now install the given conditional signal based on the jump key
        // record the connection so we can remove it later when the handler disconnects
        _udp_predicate_connections[handler_id] = _udp_predicate_signals[predicate_jump_key].connect(callback);
    }

    void unregister_udp_predicate_signal(const std::string &handler_id)
    {
        assert(_udp_predicate_connections.find(handler_id) != _udp_predicate_connections.end());
        std::shared_lock lock(_pcap_proxy_mutex);
        _udp_predicate_connections[handler_id].disconnect();
    }

    void process_udp_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp)
    {
        // first trigger generic udp signal
        udp_signal(payload, dir, l3, flowkey, stamp);

        // if we have udp predicate signals, run each predicate and conditionally trigger signals that match
        std::shared_lock lock(_pcap_proxy_mutex);
        if (_udp_predicates.size()) {
            for (const auto &[key, predicate] : _udp_predicates) {
                auto predicate_jump_key = predicate(payload, dir, l3, flowkey, stamp);
                if (_udp_predicate_signals.find(predicate_jump_key) != _udp_predicate_signals.end()) {
                    _udp_predicate_signals[predicate_jump_key](payload, dir, l3, flowkey, stamp);
                }
            }
        }
    }
    void tcp_message_ready_cb(int8_t side, const pcpp::TcpStreamData &tcpData, PacketDirection dir)
    {
        tcp_message_ready_signal(side, tcpData, dir);
    }
    void tcp_connection_start_cb(const pcpp::ConnectionData &connectionData, PacketDirection dir)
    {
        tcp_connection_start_signal(connectionData, dir);
    }
    void tcp_connection_end_cb(const pcpp::ConnectionData &connectionData, pcpp::TcpReassembly::ConnectionEndReason reason)
    {
        tcp_connection_end_signal(connectionData, reason);
    }
    void start_tstamp_cb(timespec stamp)
    {
        start_tstamp_signal(stamp);
    }
    void end_tstamp_cb(timespec stamp)
    {
        end_tstamp_signal(stamp);
    }

    void process_pcap_tcp_reassembly_error(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, timespec stamp)
    {
        tcp_reassembly_error_signal(payload, dir, l3, stamp);
    }

    void process_pcap_stats(const pcpp::IPcapDevice::PcapStats &stats)
    {
        pcap_stats_signal(stats);
    }

    // handler functionality
    // IF THIS changes, see consumer_count()
    // note: these are mutable because consumer_count() calls slot_count() which is not const (unclear if it could/should be)
    mutable sigslot::signal<pcpp::Packet &, PacketDirection, pcpp::ProtocolType, pcpp::ProtocolType, timespec> packet_signal;
    mutable sigslot::signal<pcpp::Packet &, PacketDirection, pcpp::ProtocolType, uint32_t, timespec> udp_signal;
    mutable sigslot::signal<timespec> start_tstamp_signal;
    mutable sigslot::signal<timespec> end_tstamp_signal;
    mutable sigslot::signal<int8_t, const pcpp::TcpStreamData &, PacketDirection> tcp_message_ready_signal;
    mutable sigslot::signal<const pcpp::ConnectionData &, PacketDirection> tcp_connection_start_signal;
    mutable sigslot::signal<const pcpp::ConnectionData &, pcpp::TcpReassembly::ConnectionEndReason> tcp_connection_end_signal;
    mutable sigslot::signal<pcpp::Packet &, PacketDirection, pcpp::ProtocolType, timespec> tcp_reassembly_error_signal;
    mutable sigslot::signal<const pcpp::IPcapDevice::PcapStats &> pcap_stats_signal;
};
}
