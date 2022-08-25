/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "MockInputStream.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#include "dnstap.pb.h"
#include "dns.h"
#include <Corrade/Utility/Debug.h>
#include <bitset>
#include <limits>
#include <string>

namespace visor::input::dnstap {
class DnstapInputEventProxy;
}

namespace visor::handler::dns {

using namespace visor::dns;
using namespace visor::input::pcap;
using namespace visor::input::dnstap;
using namespace visor::input::mock;

static constexpr const char *DNS_WIRE_SCHEMA{"dns"};

// DNS Groups
namespace group::wire {
enum DnsWireMetrics : visor::MetricGroupIntType {
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
    PCPP_UDP = pcpp::UDP,
    PCPP_UNKOWN = pcpp::UnknownProtocol
};

class DnsWireMetricsBucket final : public visor::AbstractMetricsBucket
{
protected:
    mutable std::shared_mutex _mutex;

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

    struct counters {
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
        Counter total;
        Counter filtered;
        Counter queryECS;
        counters()
            : queries(DNS_WIRE_SCHEMA, {"wire_packets", "queries"}, "Total DNS wire packets flagged as query (ingress and egress)")
            , replies(DNS_WIRE_SCHEMA, {"wire_packets", "replies"}, "Total DNS wire packets flagged as reply (ingress and egress)")
            , UDP(DNS_WIRE_SCHEMA, {"wire_packets", "udp"}, "Total DNS wire packets received over UDP (ingress and egress)")
            , TCP(DNS_WIRE_SCHEMA, {"wire_packets", "tcp"}, "Total DNS wire packets received over TCP (ingress and egress)")
            , DOT(DNS_WIRE_SCHEMA, {"wire_packets", "dot"}, "Total DNS wire packets received over DNS over TLS")
            , DOH(DNS_WIRE_SCHEMA, {"wire_packets", "doh"}, "Total DNS wire packets received over DNS over HTTPS")
            , IPv4(DNS_WIRE_SCHEMA, {"wire_packets", "ipv4"}, "Total DNS wire packets received over IPv4 (ingress and egress)")
            , IPv6(DNS_WIRE_SCHEMA, {"wire_packets", "ipv6"}, "Total DNS wire packets received over IPv6 (ingress and egress)")
            , NX(DNS_WIRE_SCHEMA, {"wire_packets", "nxdomain"}, "Total DNS wire packets flagged as reply with return code NXDOMAIN (ingress and egress)")
            , REFUSED(DNS_WIRE_SCHEMA, {"wire_packets", "refused"}, "Total DNS wire packets flagged as reply with return code REFUSED (ingress and egress)")
            , SRVFAIL(DNS_WIRE_SCHEMA, {"wire_packets", "srvfail"}, "Total DNS wire packets flagged as reply with return code SRVFAIL (ingress and egress)")
            , NOERROR(DNS_WIRE_SCHEMA, {"wire_packets", "noerror"}, "Total DNS wire packets flagged as reply with return code NOERROR (ingress and egress)")
            , NODATA(DNS_WIRE_SCHEMA, {"wire_packets", "nodata"}, "Total DNS wire packets flagged as reply with return code NOERROR and no answer section data (ingress and egress)")
            , total(DNS_WIRE_SCHEMA, {"wire_packets", "total"}, "Total DNS wire packets matching the configured filter(s)")
            , filtered(DNS_WIRE_SCHEMA, {"wire_packets", "filtered"}, "Total DNS wire packets seen that did not match the configured filter(s) (if any)")
            , queryECS(DNS_WIRE_SCHEMA, {"wire_packets", "query_ecs"}, "Total queries that have EDNS Client Subnet (ECS) field set")
        {
        }
    };
    counters _counters;

    Rate _rate_total;

public:
    DnsWireMetricsBucket()
        : _dns_qnameCard(DNS_WIRE_SCHEMA, {"cardinality", "qname"}, "Cardinality of unique QNAMES, both ingress and egress")
        , _dns_topGeoLocECS(DNS_WIRE_SCHEMA, "geo_loc", {"top_geoLoc_ecs"}, "Top GeoIP ECS locations")
        , _dns_topASNECS(DNS_WIRE_SCHEMA, "asn", {"top_asn_ecs"}, "Top ASNs by ECS")
        , _dns_topQueryECS(DNS_WIRE_SCHEMA, "ecs", {"top_query_ecs"}, "Top EDNS Client Subnet (ECS) observed in DNS queries")
        , _dns_topQname2(DNS_WIRE_SCHEMA, "qname", {"top_qname2"}, "Top QNAMES, aggregated at a depth of two labels")
        , _dns_topQname3(DNS_WIRE_SCHEMA, "qname", {"top_qname3"}, "Top QNAMES, aggregated at a depth of three labels")
        , _dns_topNX(DNS_WIRE_SCHEMA, "qname", {"top_nxdomain"}, "Top QNAMES with result code NXDOMAIN")
        , _dns_topREFUSED(DNS_WIRE_SCHEMA, "qname", {"top_refused"}, "Top QNAMES with result code REFUSED")
        , _dns_topSizedQnameResp(DNS_WIRE_SCHEMA, "qname", {"top_qname_by_resp_bytes"}, "Top QNAMES by response volume in bytes")
        , _dns_topSRVFAIL(DNS_WIRE_SCHEMA, "qname", {"top_srvfail"}, "Top QNAMES with result code SRVFAIL")
        , _dns_topNODATA(DNS_WIRE_SCHEMA, "qname", {"top_nodata"}, "Top QNAMES with result code NOERROR and no answer section")
        , _dns_topUDPPort(DNS_WIRE_SCHEMA, "port", {"top_udp_ports"}, "Top UDP source port on the query side of a transaction")
        , _dns_topQType(DNS_WIRE_SCHEMA, "qtype", {"top_qtype"}, "Top query types")
        , _dns_topRCode(DNS_WIRE_SCHEMA, "rcode", {"top_rcode"}, "Top result codes")
        , _rate_total(DNS_WIRE_SCHEMA, {"rates", "total"}, "Rate of all DNS wire packets (combined ingress and egress) in packets per second")
    {
        set_event_rate_info(DNS_WIRE_SCHEMA, {"rates", "events"}, "Rate of all DNS wire packets before filtering per second");
        set_num_events_info(DNS_WIRE_SCHEMA, {"wire_packets", "events"}, "Total DNS wire packets events");
        set_num_sample_info(DNS_WIRE_SCHEMA, {"wire_packets", "deep_samples"}, "Total DNS wire packets that were sampled for deep inspection");
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
    }

    void on_set_read_only() override
    {
        // stop rate collection
        _rate_total.cancel();
    }

    void process_filtered();
    void process_dns_layer(bool deep, DnsLayer &payload, pcpp::ProtocolType l3, Protocol l4, uint16_t port, size_t suffix_size = 0);
    void process_dns_layer(pcpp::ProtocolType l3, Protocol l4, QR side, uint16_t port);
    void process_dnstap(bool deep, const dnstap::Dnstap &payload);
};

class DnsWireMetricsManager final : public visor::AbstractMetricsManager<DnsWireMetricsBucket>
{
public:
    DnsWireMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<DnsWireMetricsBucket>(window_config)
    {
    }

    void process_filtered(timespec stamp);
    void process_dns_layer(DnsLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowkey, uint16_t port, size_t suffix_size, timespec stamp);
    void process_dnstap(const dnstap::Dnstap &payload, bool filtered);
};

class DnsWireTcpSessionData final : public TcpSessionData
{
public:
    static constexpr size_t MIN_DNS_QUERY_SIZE = 17;

    DnsWireTcpSessionData(got_msg_cb got_data_handler)
        : TcpSessionData(got_data_handler)
    {
    }

    ~DnsWireTcpSessionData() = default;

    void receive_tcp_data(const uint8_t *data, size_t len) override;
};

class DnsWireStreamHandler final : public visor::StreamMetricsHandler<DnsWireMetricsManager>
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
        OnlyQtype,
        AnswerCount,
        OnlyQNameSuffix,
        OnlyDNSSECResponse,
        DnstapMsgType,
        GeoLocNotFound,
        AsnNotFound,
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
    std::vector<uint16_t> _f_qtypes;
    size_t _static_suffix_size{0};
    std::bitset<DNSTAP_TYPE_SIZE> _f_dnstap_types;
    bool _using_predicate_signals{false};

    static const inline StreamMetricsHandler::GroupDefType _group_defs = {
        {"cardinality", group::wire::DnsWireMetrics::Cardinality},
        {"counters", group::wire::DnsWireMetrics::Counters},
        {"dns_transaction", group::wire::DnsWireMetrics::DnsTransactions},
        {"top_ecs", group::wire::DnsWireMetrics::TopEcs},
        {"top_qnames", group::wire::DnsWireMetrics::TopQnames}};

    bool _filtering(DnsLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint16_t port, timespec stamp);
    bool _configs(DnsLayer &payload);
    void _register_predicate_filter(Filters filter, std::string f_key, std::string f_value);

public:
    DnsWireStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config);
    ~DnsWireStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return DNS_WIRE_SCHEMA;
    }

    void start() override;
    void stop() override;
    void info_json(json &j) const override;
};
}
