/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "MockInputStream.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#include "dns.h"
#include "dnstap.pb.h"
#include "querypairmgr.h"
#include <Corrade/Utility/Debug.h>
#include <bitset>
#include <limits>
#include <string>

namespace visor::input::dnstap {
class DnstapInputEventProxy;
}

namespace visor::handler::dns {

using namespace visor::input::pcap;
using namespace visor::input::dnstap;
using namespace visor::input::mock;

// DNS Groups
namespace group {
enum DnsMetrics : visor::MetricGroupIntType {
    Cardinality,
    Counters,
    DnsTransactions,
    TopEcs,
    TopQnames
};
}

enum Protocol : uint64_t {
    DNSTAP_UDP = dnstap::SocketProtocol::UDP,
    DNSTAP_TCP = dnstap::SocketProtocol::TCP,
    DNSTAP_DOT = dnstap::SocketProtocol::DOT,
    DNSTAP_DOH = dnstap::SocketProtocol::DOH,
    PCPP_TCP = pcpp::TCP,
    PCPP_UDP = pcpp::UDP
};

class DnsMetricsBucket final : public visor::AbstractMetricsBucket
{
protected:
    mutable std::shared_mutex _mutex;

    Quantile<uint64_t> _dnsXactFromTimeUs;
    Quantile<uint64_t> _dnsXactToTimeUs;
    Quantile<double> _dnsXactRatio;

    Cardinality _dns_qnameCard;

    TopN<std::string> _dns_topGeoLocECS;
    TopN<std::string> _dns_topASNECS;
    TopN<std::string> _dns_topQueryECS;

    TopN<std::string> _dns_topQname2;
    TopN<std::string> _dns_topQname3;
    TopN<std::string> _dns_topNX;
    TopN<std::string> _dns_topREFUSED;
    TopN<std::string> _dns_topSizedQnameResp;
    TopN<std::string> _dns_topSRVFAIL;
    TopN<std::string> _dns_topNODATA;
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
        Counter DOT;
        Counter DOH;
        Counter IPv4;
        Counter IPv6;
        Counter NX;
        Counter REFUSED;
        Counter SRVFAIL;
        Counter NOERROR;
        Counter NODATA;
        Counter filtered;
        counters()
            : xacts_total("dns", {"xact", "counts", "total"}, "Total DNS transactions (query/reply pairs)")
            , xacts_in("dns", {"xact", "in", "total"}, "Total ingress DNS transactions (host is server)")
            , xacts_out("dns", {"xact", "out", "total"}, "Total egress DNS transactions (host is client)")
            , xacts_timed_out("dns", {"xact", "counts", "timed_out"}, "Total number of DNS transactions that timed out")
            , queries("dns", {"wire_packets", "queries"}, "Total DNS wire packets flagged as query (ingress and egress)")
            , replies("dns", {"wire_packets", "replies"}, "Total DNS wire packets flagged as reply (ingress and egress)")
            , UDP("dns", {"wire_packets", "udp"}, "Total DNS wire packets received over UDP (ingress and egress)")
            , TCP("dns", {"wire_packets", "tcp"}, "Total DNS wire packets received over TCP (ingress and egress)")
            , DOT("dns", {"wire_packets", "dot"}, "Total DNS wire packets received over DNS over TLS")
            , DOH("dns", {"wire_packets", "doh"}, "Total DNS wire packets received over DNS over HTTPS")
            , IPv4("dns", {"wire_packets", "ipv4"}, "Total DNS wire packets received over IPv4 (ingress and egress)")
            , IPv6("dns", {"wire_packets", "ipv6"}, "Total DNS wire packets received over IPv6 (ingress and egress)")
            , NX("dns", {"wire_packets", "nxdomain"}, "Total DNS wire packets flagged as reply with return code NXDOMAIN (ingress and egress)")
            , REFUSED("dns", {"wire_packets", "refused"}, "Total DNS wire packets flagged as reply with return code REFUSED (ingress and egress)")
            , SRVFAIL("dns", {"wire_packets", "srvfail"}, "Total DNS wire packets flagged as reply with return code SRVFAIL (ingress and egress)")
            , NOERROR("dns", {"wire_packets", "noerror"}, "Total DNS wire packets flagged as reply with return code NOERROR (ingress and egress)")
            , NODATA("dns", {"wire_packets", "nodata"}, "Total DNS wire packets flagged as reply with return code NOERROR and no answer section data (ingress and egress)")
            , filtered("dns", {"wire_packets", "filtered"}, "Total DNS wire packets seen that did not match the configured filter(s) (if any)")
        {
        }
    };
    counters _counters;

public:
    DnsMetricsBucket()
        : _dnsXactFromTimeUs("dns", {"xact", "out", "quantiles_us"}, "Quantiles of transaction timing (query/reply pairs) when host is client, in microseconds")
        , _dnsXactToTimeUs("dns", {"xact", "in", "quantiles_us"}, "Quantiles of transaction timing (query/reply pairs) when host is server, in microseconds")
        , _dnsXactRatio("dns", {"xact", "ratio", "quantiles"}, "Quantiles of ratio of packet sizes in a DNS transaction (reply/query)")
        , _dns_qnameCard("dns", {"cardinality", "qname"}, "Cardinality of unique QNAMES, both ingress and egress")
        , _dns_topGeoLocECS("dns", "geo_loc", {"top_geoLoc_ecs"}, "Top GeoIP ECS locations")
        , _dns_topASNECS("dns", "asn", {"top_asn_ecs"}, "Top ASNs by ECS")
        , _dns_topQueryECS("dns", "ecs", {"top_query_ecs"}, "Top EDNS Client Subnet (ECS) observed in DNS queries")
        , _dns_topQname2("dns", "qname", {"top_qname2"}, "Top QNAMES, aggregated at a depth of two labels")
        , _dns_topQname3("dns", "qname", {"top_qname3"}, "Top QNAMES, aggregated at a depth of three labels")
        , _dns_topNX("dns", "qname", {"top_nxdomain"}, "Top QNAMES with result code NXDOMAIN")
        , _dns_topREFUSED("dns", "qname", {"top_refused"}, "Top QNAMES with result code REFUSED")
        , _dns_topSizedQnameResp("dns", "qname", {"top_qname_by_resp_bytes"}, "Top QNAMES by response volume in bytes")
        , _dns_topSRVFAIL("dns", "qname", {"top_srvfail"}, "Top QNAMES with result code SRVFAIL")
        , _dns_topNODATA("dns", "qname", {"top_nodata"}, "Top QNAMES with result code NOERROR and no answer section")
        , _dns_topUDPPort("dns", "port", {"top_udp_ports"}, "Top UDP source port on the query side of a transaction")
        , _dns_topQType("dns", "qtype", {"top_qtype"}, "Top query types")
        , _dns_topRCode("dns", "rcode", {"top_rcode"}, "Top result codes")
        , _dns_slowXactIn("dns", "qname", {"xact", "in", "top_slow"}, "Top QNAMES in transactions where host is the server and transaction speed is slower than p90")
        , _dns_slowXactOut("dns", "qname", {"xact", "out", "top_slow"}, "Top QNAMES in transactions where host is the client and transaction speed is slower than p90")
    {
        set_event_rate_info("dns", {"rates", "total"}, "Rate of all DNS wire packets (combined ingress and egress) per second");
        set_num_events_info("dns", {"wire_packets", "total"}, "Total DNS wire packets");
        set_num_sample_info("dns", {"wire_packets", "deep_samples"}, "Total DNS wire packets that were sampled for deep inspection");
    }

    auto get_xact_data_locked() const
    {
        std::shared_lock lock(_mutex);
        struct retVals {
            const Quantile<uint64_t> &xact_to;
            const Quantile<uint64_t> &xact_from;
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
    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override;
    void update_topn_metrics(size_t topn_count) override
    {
        _dns_topGeoLocECS.set_topn_count(topn_count);
        _dns_topASNECS.set_topn_count(topn_count);
        _dns_topQueryECS.set_topn_count(topn_count);
        _dns_topQname2.set_topn_count(topn_count);
        _dns_topQname3.set_topn_count(topn_count);
        _dns_topNX.set_topn_count(topn_count);
        _dns_topREFUSED.set_topn_count(topn_count);
        _dns_topSizedQnameResp.set_topn_count(topn_count);
        _dns_topSRVFAIL.set_topn_count(topn_count);
        _dns_topNODATA.set_topn_count(topn_count);
        _dns_topUDPPort.set_topn_count(topn_count);
        _dns_topQType.set_topn_count(topn_count);
        _dns_topRCode.set_topn_count(topn_count);
        _dns_slowXactIn.set_topn_count(topn_count);
        _dns_slowXactOut.set_topn_count(topn_count);
    }

    void process_filtered();
    void process_dns_layer(bool deep, DnsLayer &payload, pcpp::ProtocolType l3, Protocol l4, uint16_t port, size_t suffix_size = 0);
    void process_dns_layer(pcpp::ProtocolType l3, Protocol l4, QR side, uint16_t port);
    void process_dnstap(bool deep, const dnstap::Dnstap &payload);

    void new_dns_transaction(bool deep, float to90th, float from90th, DnsLayer &dns, PacketDirection dir, DnsTransaction xact);
};

class DnsMetricsManager final : public visor::AbstractMetricsManager<DnsMetricsBucket>
{
    QueryResponsePairMgr _qr_pair_manager;
    float _to90th{0.0};
    float _from90th{0.0};

public:
    DnsMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<DnsMetricsBucket>(window_config)
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

    void process_filtered(timespec stamp);
    void process_dns_layer(DnsLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowkey, uint16_t port, size_t suffix_size, timespec stamp);
    void process_dnstap(const dnstap::Dnstap &payload, bool filtered);
};

class TcpSessionData final
{
public:
    static constexpr size_t MIN_DNS_QUERY_SIZE = 17;
    using got_msg_cb = std::function<void(std::unique_ptr<uint8_t[]> data, size_t size)>;

private:
    std::string _buffer;
    got_msg_cb _got_dns_msg;
    bool _invalid_data;

public:
    TcpSessionData(
        got_msg_cb got_data_handler)
        : _got_dns_msg{std::move(got_data_handler)}
        , _invalid_data(false)
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
    static constexpr size_t DNSTAP_TYPE_SIZE = 15;

    struct DnsCacheData {
        uint32_t flowKey = 0;
        timespec timestamp = timespec();
        std::unique_ptr<DnsLayer> dnsLayer;
    };
    static thread_local DnsCacheData _cached_dns_layer;

    // the input event proxy we support (only one will be in use at a time)
    PcapInputEventProxy *_pcap_proxy{nullptr};
    MockInputEventProxy *_mock_proxy{nullptr};
    DnstapInputEventProxy *_dnstap_proxy{nullptr};

    typedef uint32_t flowKey;
    std::unordered_map<flowKey, TcpFlowData> _tcp_connections;

    sigslot::connection _dnstap_connection;

    sigslot::connection _pkt_udp_connection;
    sigslot::connection _start_tstamp_connection;
    sigslot::connection _end_tstamp_connection;

    sigslot::connection _tcp_start_connection;
    sigslot::connection _tcp_end_connection;
    sigslot::connection _tcp_message_connection;

    sigslot::connection _heartbeat_connection;

    void process_udp_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp);
    void process_dnstap_cb(const dnstap::Dnstap &, size_t);
    void tcp_message_ready_cb(int8_t side, const pcpp::TcpStreamData &tcpData);
    void tcp_connection_start_cb(const pcpp::ConnectionData &connectionData);
    void tcp_connection_end_cb(const pcpp::ConnectionData &connectionData, pcpp::TcpReassembly::ConnectionEndReason reason);
    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

    static const inline std::map<std::string, std::pair<int, int>> _dnstap_map_types = {
        {"auth", {dnstap::Message_Type_AUTH_QUERY, dnstap::Message_Type_AUTH_RESPONSE}},
        {"resolver", {dnstap::Message_Type_RESOLVER_QUERY, dnstap::Message_Type_RESOLVER_RESPONSE}},
        {"client", {dnstap::Message_Type_CLIENT_QUERY, dnstap::Message_Type_CLIENT_RESPONSE}},
        {"forwarder", {dnstap::Message_Type_FORWARDER_QUERY, dnstap::Message_Type_FORWARDER_RESPONSE}},
        {"stub", {dnstap::Message_Type_STUB_QUERY, dnstap::Message_Type_STUB_RESPONSE}},
        {"tool", {dnstap::Message_Type_TOOL_QUERY, dnstap::Message_Type_TOOL_RESPONSE}},
        {"update", {dnstap::Message_Type_UPDATE_QUERY, dnstap::Message_Type_UPDATE_RESPONSE}}};

    // DNS Filters
    enum Filters {
        ExcludingRCode,
        OnlyRCode,
        AnswerCount,
        OnlyQNameSuffix,
        OnlyDNSSECResponse,
        DnstapMsgType,
        FiltersMAX
    };
    std::bitset<Filters::FiltersMAX> _f_enabled;
    enum Configs {
        PublicSuffixList,
        ConfigsMAX
    };
    std::bitset<Configs::ConfigsMAX> _c_enabled;
    uint16_t _f_rcode{0};
    uint64_t _f_answer_count{0};
    std::vector<std::string> _f_qnames;
    size_t _static_suffix_size{0};
    std::bitset<DNSTAP_TYPE_SIZE> _f_dnstap_types;

    static const inline StreamMetricsHandler::GroupDefType _group_defs = {
        {"cardinality", group::DnsMetrics::Cardinality},
        {"counters", group::DnsMetrics::Counters},
        {"dns_transaction", group::DnsMetrics::DnsTransactions},
        {"top_ecs", group::DnsMetrics::TopEcs},
        {"top_qnames", group::DnsMetrics::TopQnames}};

    bool _filtering(DnsLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint16_t port, timespec stamp);
    bool _configs(DnsLayer &payload);

public:
    DnsStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config, StreamHandler *handler = nullptr);
    ~DnsStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "dns";
    }

    size_t consumer_count() const override
    {
        return udp_signal.slot_count();
    }

    void start() override;
    void stop() override;
    void info_json(json &j) const override;

    mutable sigslot::signal<timespec> start_tstamp_signal;
    mutable sigslot::signal<timespec> end_tstamp_signal;
    mutable sigslot::signal<const timespec> heartbeat_signal;
    mutable sigslot::signal<pcpp::Packet &, PacketDirection, pcpp::ProtocolType, uint32_t, timespec> udp_signal;
};

}
