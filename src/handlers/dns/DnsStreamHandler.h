#pragma once

#include "AbstractMetricsManager.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#include "dns.h"
#include "querypairmgr.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-function"
#include <cpc_sketch.hpp>
#include <frequent_items_sketch.hpp>
#include <kll_sketch.hpp>
#pragma GCC diagnostic pop
#include <Corrade/Utility/Debug.h>
#include <string>

namespace vizer::handler::dns {

using namespace vizer::input::pcap;

class DnsMetricsBucket final : public vizer::AbstractMetricsBucket
{
public:
    const uint8_t START_FI_MAP_SIZE = 7; // 2^7 = 128
    const uint8_t MAX_FI_MAP_SIZE = 13;  // 2^13 = 8192

protected:
    mutable std::shared_mutex _mutex;

    datasketches::kll_sketch<uint64_t> _dnsXactFromTimeUs;
    datasketches::kll_sketch<uint64_t> _dnsXactToTimeUs;

    datasketches::cpc_sketch _dns_qnameCard;

    datasketches::frequent_items_sketch<std::string> _dns_topQname2;
    datasketches::frequent_items_sketch<std::string> _dns_topQname3;
    datasketches::frequent_items_sketch<std::string> _dns_topNX;
    datasketches::frequent_items_sketch<std::string> _dns_topREFUSED;
    datasketches::frequent_items_sketch<std::string> _dns_topSRVFAIL;
    datasketches::frequent_items_sketch<uint16_t> _dns_topUDPPort;
    datasketches::frequent_items_sketch<uint16_t> _dns_topQType;
    datasketches::frequent_items_sketch<uint16_t> _dns_topRCode;
    datasketches::frequent_items_sketch<std::string> _dns_slowXactIn;
    datasketches::frequent_items_sketch<std::string> _dns_slowXactOut;

    struct counters {
        uint64_t xacts_total = 0;
        uint64_t xacts_in = 0;
        uint64_t xacts_out = 0;
        uint64_t queries = 0;
        uint64_t replies = 0;
        uint64_t UDP = 0;
        uint64_t TCP = 0;
        uint64_t IPv4 = 0;
        uint64_t IPv6 = 0;
        uint64_t NX = 0;
        uint64_t REFUSED = 0;
        uint64_t SRVFAIL = 0;
        uint64_t NOERROR = 0;
    };
    counters _counters;

public:
    DnsMetricsBucket()
        : _dnsXactFromTimeUs()
        , _dnsXactToTimeUs()
        , _dns_qnameCard()
        , _dns_topQname2(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_topQname3(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_topNX(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_topREFUSED(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_topSRVFAIL(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_topUDPPort(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_topQType(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_topRCode(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_slowXactIn(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_slowXactOut(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _counters()
    {
    }

    auto get_xact_data_locked()
    {
        std::shared_lock lock(_mutex);
        struct retVals {
            datasketches::kll_sketch<uint64_t> &xact_to;
            datasketches::kll_sketch<uint64_t> &xact_from;
            std::shared_lock<std::shared_mutex> lock;
        };
        return retVals{_dnsXactToTimeUs, _dnsXactFromTimeUs, std::move(lock)};
    }

    // get a copy of the counters
    counters counters() const
    {
        std::shared_lock lock(_mutex);
        return _counters;
    }

    // vizer::AbstractMetricsBucket
    void specialized_merge(const AbstractMetricsBucket &other) override;
    void to_json(json &j) const override;

    void process_dns_layer(bool deep, DnsLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowkey, uint16_t port, timespec stamp);

    void newDNSXact(bool deep, float to90th, float from90th, DnsLayer &dns, PacketDirection dir, DnsTransaction xact);
};

class DnsMetricsManager final : public vizer::AbstractMetricsManager<DnsMetricsBucket>
{

    QueryResponsePairMgr _qr_pair_manager;
    float _to90th = 0.0;
    float _from90th = 0.0;
    uint64_t _sample_threshold = 10;

public:
    DnsMetricsManager(uint periods, int deepSampleRate)
        : vizer::AbstractMetricsManager<DnsMetricsBucket>(periods, deepSampleRate)
    {
    }

    void on_period_shift(timespec stamp) override
    {
        // DNS transaction support
        _qr_pair_manager.purgeOldTransactions(stamp);
        auto [xact_to, xact_from, lock] = _metric_buckets.back()->get_xact_data_locked();
        if (xact_from.get_n() > _sample_threshold) {
            _from90th = xact_from.get_quantile(0.90);
        }
        if (xact_to.get_n() > _sample_threshold) {
            _to90th = xact_to.get_quantile(0.90);
        }
    }

    size_t num_open_transactions() const
    {
        return _qr_pair_manager.getOpenTransactionCount();
    }

    void process_dns_layer(DnsLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowkey, uint16_t port, timespec stamp);
};

class TcpSessionData final
{
public:
    using got_msg_cb = std::function<void(std::unique_ptr<uint8_t[]> data, size_t size)>;

private:
    std::string _buffer;
    got_msg_cb _got_dns_msg;

public:
    TcpSessionData(
        got_msg_cb got_data_handler)
        : _got_dns_msg{std::move(got_data_handler)}
    {
    }

    // called from pcpp::TcpReassembly callback, matches types
    void receive_dns_wire_data(const uint8_t *data, size_t len);
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

class DnsStreamHandler final : public vizer::StreamMetricsHandler<DnsMetricsManager>
{

    PcapInputStream *_stream;

    typedef uint32_t flowKey;
    std::unordered_map<flowKey, TcpFlowData> _tcp_connections;

    sigslot::connection _pkt_udp_connection;
    sigslot::connection _start_tstamp_connection;

    sigslot::connection _tcp_start_connection;
    sigslot::connection _tcp_end_connection;
    sigslot::connection _tcp_message_connection;

    void process_udp_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp);
    void tcp_message_ready_cb(int8_t side, const pcpp::TcpStreamData &tcpData);
    void tcp_connection_start_cb(const pcpp::ConnectionData &connectionData);
    void tcp_connection_end_cb(const pcpp::ConnectionData &connectionData, pcpp::TcpReassembly::ConnectionEndReason reason);
    void set_initial_tstamp(timespec stamp);

public:
    DnsStreamHandler(const std::string &name, PcapInputStream *stream, uint periods, int deepSampleRate);
    ~DnsStreamHandler() override;

    // vizer::AbstractModule
    void start() override;
    void stop() override;
    json info_json() const override;

    // vizer::StreamMetricsHandler
    void to_json(json &j, uint64_t period, bool merged) override;
};

}
