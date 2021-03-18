/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#include "dns.h"
#include "querypairmgr.h"
#include <Corrade/Utility/Debug.h>
#include <string>

namespace visor::handler::dns {

using namespace visor::input::pcap;

class DnsMetricsBucket final : public visor::AbstractMetricsBucket
{
public:
    const uint8_t START_FI_MAP_SIZE = 7; // 2^7 = 128
    const uint8_t MAX_FI_MAP_SIZE = 13;  // 2^13 = 8192

protected:
    mutable std::shared_mutex _mutex;

    Quantile<uint64_t> _dnsXactFromTimeUs;
    Quantile<uint64_t> _dnsXactToTimeUs;

    Cardinality _dns_qnameCard;

    TopN<std::string> _dns_topQname2;
    TopN<std::string> _dns_topQname3;
    TopN<std::string> _dns_topNX;
    TopN<std::string> _dns_topREFUSED;
    TopN<std::string> _dns_topSRVFAIL;
    TopN<uint16_t> _dns_topUDPPort;
    TopN<uint16_t> _dns_topQType;
    TopN<uint16_t> _dns_topRCode;
    TopN<std::string> _dns_slowXactIn;
    TopN<std::string> _dns_slowXactOut;

    struct counters {
        Counter xacts_total;
        Counter xacts_in;
        Counter xacts_out;
        Counter xacts_timed_out;
        Counter queries;
        Counter replies;
        Counter UDP;
        Counter TCP;
        Counter IPv4;
        Counter IPv6;
        Counter NX;
        Counter REFUSED;
        Counter SRVFAIL;
        Counter NOERROR;
        counters()
            : xacts_total("total", "Total DNS transactions (query/reply pairs)")
            , xacts_in("in", "Total ingress DNS transactions (host is server)")
            , xacts_out("out", "Total egress DNS transactions (host is client)")
            , xacts_timed_out("timed_out", "Total number of DNS transactions that timed out")
            , queries("queries", "Total DNS wire packets flagged as query (ingress and egress)")
            , replies("replies", "Total DNS wire packets flagged as reply (ingress and egress)")
            , UDP("udp", "Total DNS wire packets received over UDP (ingress and egress)")
            , TCP("tcp", "Total DNS wire packets received over TCP (ingress and egress)")
            , IPv4("ipv4", "Total DNS wire packets received over IPv4 (ingress and egress)")
            , IPv6("ipv6", "Total DNS wire packets received over IPv6 (ingress and egress)")
            , NX("nxdomain", "Total DNS wire packets flagged as reply with return code NXDOMAIN (ingress and egress)")
            , REFUSED("refused", "Total DNS wire packets flagged as reply with return code REFUSED (ingress and egress)")
            , SRVFAIL("srvfail", "Total DNS wire packets flagged as reply with return code SRVFAIL (ingress and egress)")
            , NOERROR("noerror", "Total DNS wire packets flagged as reply with return code NOERROR (ingress and egress)")
        {
        }
    };
    counters _counters;

public:
    DnsMetricsBucket()
        : _dnsXactFromTimeUs({"xact", "out", "quantiles_us"}, "")
        , _dnsXactToTimeUs("", "")
        , _dns_qnameCard("", "")
        , _dns_topQname2("", "")
        , _dns_topQname3("", "")
        , _dns_topNX("", "")
        , _dns_topREFUSED("", "")
        , _dns_topSRVFAIL("", "")
        , _dns_topUDPPort("", "")
        , _dns_topQType("", "")
        , _dns_topRCode("", "")
        , _dns_slowXactIn("", "")
        , _dns_slowXactOut("", "")
    {
    }

    auto get_xact_data_locked() const
    {
        std::shared_lock lock(_mutex);
        struct retVals {
            const datasketches::kll_sketch<uint64_t> &xact_to;
            const datasketches::kll_sketch<uint64_t> &xact_from;
            std::shared_lock<std::shared_mutex> lock;
        };
        return retVals{_dnsXactToTimeUs, _dnsXactFromTimeUs, std::move(lock)};
    }

    void inc_xact_timed_out(uint64_t c)
    {
        std::unique_lock lock(_mutex);
        _counters.xacts_timed_out += c;
    }

    // get a copy of the counters
    counters counters() const
    {
        std::shared_lock lock(_mutex);
        return _counters;
    }

    // visor::AbstractMetricsBucket
    void specialized_merge(const AbstractMetricsBucket &other) override;
    void to_json(json &j) const override;
    void to_prometheus(std::stringstream &out, const std::string &key) const override;

    void process_dns_layer(bool deep, DnsLayer &payload, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint16_t port);

    void new_dns_transaction(bool deep, float to90th, float from90th, DnsLayer &dns, PacketDirection dir, DnsTransaction xact);
};

class DnsMetricsManager final : public visor::AbstractMetricsManager<DnsMetricsBucket>
{

    QueryResponsePairMgr _qr_pair_manager;
    float _to90th = 0.0;
    float _from90th = 0.0;

public:
    DnsMetricsManager(uint periods, int deepSampleRate)
        : visor::AbstractMetricsManager<DnsMetricsBucket>(periods, deepSampleRate)
    {
    }

    void on_period_shift(timespec stamp, [[maybe_unused]] const DnsMetricsBucket *maybe_expiring_bucket) override
    {
        // DNS transaction support
        auto timed_out = _qr_pair_manager.purge_old_transactions(stamp);
        if (timed_out) {
            live_bucket()->inc_xact_timed_out(timed_out);
        }
        // collect to/from 90th percentile every period shift to judge slow xacts
        auto [xact_to, xact_from, lock] = bucket(1)->get_xact_data_locked();
        if (xact_from.get_n()) {
            _from90th = xact_from.get_quantile(0.90);
        }
        if (xact_to.get_n()) {
            _to90th = xact_to.get_quantile(0.90);
        }
    }

    size_t num_open_transactions() const
    {
        return _qr_pair_manager.open_transaction_count();
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

class DnsStreamHandler final : public visor::StreamMetricsHandler<DnsMetricsManager>
{

    PcapInputStream *_stream;

    typedef uint32_t flowKey;
    std::unordered_map<flowKey, TcpFlowData> _tcp_connections;

    sigslot::connection _pkt_udp_connection;
    sigslot::connection _start_tstamp_connection;
    sigslot::connection _end_tstamp_connection;

    sigslot::connection _tcp_start_connection;
    sigslot::connection _tcp_end_connection;
    sigslot::connection _tcp_message_connection;

    void process_udp_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp);
    void tcp_message_ready_cb(int8_t side, const pcpp::TcpStreamData &tcpData);
    void tcp_connection_start_cb(const pcpp::ConnectionData &connectionData);
    void tcp_connection_end_cb(const pcpp::ConnectionData &connectionData, pcpp::TcpReassembly::ConnectionEndReason reason);
    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

public:
    DnsStreamHandler(const std::string &name, PcapInputStream *stream, uint periods, int deepSampleRate);
    ~DnsStreamHandler() override;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "dns";
    }
    void start() override;
    void stop() override;
    void info_json(json &j) const override;

    // visor::StreamHandler
    void window_json(json &j, uint64_t period, bool merged) override;
    void window_prometheus(std::stringstream &out) override;
};

}
