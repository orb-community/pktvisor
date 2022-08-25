/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "MockInputStream.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#include "dnstap.pb.h"
#include "querypairmgr.h"
#include "visor_dns/dns.h"
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

static constexpr const char *DNS_XACT_SCHEMA{"dns"};

// DNS Groups
namespace group::xact {
enum DnsXactMetrics : visor::MetricGroupIntType {
    Cardinality,
    Counters,
    DnsTransactions,
    TopEcs,
    TopQnames
};
}

class DnsXactMetricsBucket final : public visor::AbstractMetricsBucket
{
protected:
    mutable std::shared_mutex _mutex;

    Quantile<uint64_t> _dnsXactFromTimeUs;
    Quantile<uint64_t> _dnsXactToTimeUs;
    Quantile<double> _dnsXactRatio;

    TopN<std::string> _dns_slowXactIn;
    TopN<std::string> _dns_slowXactOut;

    struct counters {
        Counter xacts_total;
        Counter xacts_in;
        Counter xacts_out;
        Counter xacts_unknown_dir;
        Counter xacts_timed_out;
        Counter xacts_filtered;
        counters()
            : xacts_total(DNS_XACT_SCHEMA, {"xact", "counts", "total"}, "Total DNS transactions (query/reply pairs)")
            , xacts_in(DNS_XACT_SCHEMA, {"xact", "in", "total"}, "Total ingress DNS transactions (host is server)")
            , xacts_out(DNS_XACT_SCHEMA, {"xact", "out", "total"}, "Total egress DNS transactions (host is client)")
            , xacts_unknown_dir(DNS_XACT_SCHEMA, {"xact", "counts", "unknown_dir"}, "Total DNS transactions with unknown direction")
            , xacts_timed_out(DNS_XACT_SCHEMA, {"xact", "counts", "timed_out"}, "Total number of DNS transactions that timed out")
            , xacts_filtered(DNS_XACT_SCHEMA, {"xact", "counts", "filtered"}, "Total DNS transactions seen that did not match the configured filter(s) (if any)")
        {
        }
    };
    counters _counters;

    Rate _rate_total;

public:
    DnsXactMetricsBucket()
        : _dnsXactFromTimeUs(DNS_XACT_SCHEMA, {"xact", "out", "quantiles_us"}, "Quantiles of transaction timing (query/reply pairs) when host is client, in microseconds")
        , _dnsXactToTimeUs(DNS_XACT_SCHEMA, {"xact", "in", "quantiles_us"}, "Quantiles of transaction timing (query/reply pairs) when host is server, in microseconds")
        , _dnsXactRatio(DNS_XACT_SCHEMA, {"xact", "ratio", "quantiles"}, "Quantiles of ratio of packet sizes in a DNS transaction (reply/query)")
        , _dns_slowXactIn(DNS_XACT_SCHEMA, "qname", {"xact", "in", "top_slow"}, "Top QNAMES in transactions where host is the server and transaction speed is slower than p90")
        , _dns_slowXactOut(DNS_XACT_SCHEMA, "qname", {"xact", "out", "top_slow"}, "Top QNAMES in transactions where host is the client and transaction speed is slower than p90")
        , _rate_total(DNS_XACT_SCHEMA, {"xact", "rates", "total"}, "Rate of all DNS transaction (combined ingress and egress) in packets per second")
    {
        set_event_rate_info(DNS_XACT_SCHEMA, {"xact", "rates", "events"}, "Rate of all DNS wire packets before filtering per second");
        set_num_events_info(DNS_XACT_SCHEMA, {"xact", "counts", "events"}, "Total DNS wire packets events");
        set_num_sample_info(DNS_XACT_SCHEMA, {"xact", "counts", "deep_samples"}, "Total DNS wire packets that were sampled for deep inspection");
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
        _dns_slowXactIn.set_topn_count(topn_count);
        _dns_slowXactOut.set_topn_count(topn_count);
    }

    void on_set_read_only() override
    {
        // stop rate collection
        _rate_total.cancel();
    }

    void process_filtered();
    void new_dns_transaction(bool deep, float to90th, float from90th, DnsLayer &dns, PacketDirection dir, DnsTransaction xact);
};

class DnsXactMetricsManager final : public visor::AbstractMetricsManager<DnsXactMetricsBucket>
{
    QueryResponsePairMgr _qr_pair_manager;
    float _to90th{0.0};
    float _from90th{0.0};

public:
    DnsXactMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<DnsXactMetricsBucket>(window_config)
    {
    }

    void on_period_shift(timespec stamp, [[maybe_unused]] const DnsXactMetricsBucket *maybe_expiring_bucket) override
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

    void process_filtered(timespec stamp, bool response, uint32_t flowKey, uint16_t transactionID);
    void process_dns_layer(DnsLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowkey, uint16_t port, size_t suffix_size, timespec stamp);
    void process_dnstap(const dnstap::Dnstap &payload, bool filtered);
};

class DnsXactTcpSessionData final : public TcpSessionData
{
public:
    static constexpr size_t MIN_DNS_QUERY_SIZE = 17;

    DnsXactTcpSessionData(got_msg_cb got_data_handler)
        : TcpSessionData(got_data_handler)
    {
    }

    ~DnsXactTcpSessionData() = default;

    void receive_tcp_data(const uint8_t *data, size_t len) override;
};

class DnsXactStreamHandler final : public visor::StreamMetricsHandler<DnsXactMetricsManager>
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
        {"cardinality", group::xact::DnsXactMetrics::Cardinality},
        {"counters", group::xact::DnsXactMetrics::Counters},
        {"dns_transaction", group::xact::DnsXactMetrics::DnsTransactions},
        {"top_ecs", group::xact::DnsXactMetrics::TopEcs},
        {"top_qnames", group::xact::DnsXactMetrics::TopQnames}};

    bool _filtering(DnsLayer &payload, [[maybe_unused]] PacketDirection dir, uint32_t flowkey, timespec stamp);
    bool _configs(DnsLayer &payload);
    void _register_predicate_filter(Filters filter, std::string f_key, std::string f_value);

public:
    DnsXactStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config);
    ~DnsXactStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return DNS_XACT_SCHEMA;
    }

    void start() override;
    void stop() override;
    void info_json(json &j) const override;
};
}
