/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "DnsStreamHandler.h"
#include "DnstapInputStream.h"
#include "MockInputStream.h"
#include "PcapInputStream.h"
#include "SflowInputStream.h"
#include "StreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <string>

namespace visor::handler::net {

using namespace visor::input::pcap;
using namespace visor::input::dnstap;
using namespace visor::input::mock;
using namespace visor::input::sflow;
using namespace visor::handler::dns;

namespace group {
enum NetMetrics : visor::MetricGroupIntType {
    Counters,
    Cardinality,
    TopGeo,
    TopIps
};
}

class NetworkMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;

    Cardinality _srcIPCard;
    Cardinality _dstIPCard;

    TopN<std::string> _topGeoLoc;
    TopN<std::string> _topASN;
    TopN<uint32_t> _topIPv4;
    TopN<std::string> _topIPv6;

    // total numPackets is tracked in base class num_events
    struct counters {
        Counter UDP;
        Counter TCP;
        Counter OtherL4;
        Counter IPv4;
        Counter IPv6;
        Counter total_in;
        Counter total_out;
        counters()
            : UDP("packets", {"udp"}, "Count of UDP packets")
            , TCP("packets", {"tcp"}, "Count of TCP packets")
            , OtherL4("packets", {"other_l4"}, "Count of packets which are not UDP or TCP")
            , IPv4("packets", {"ipv4"}, "Count of IPv4 packets")
            , IPv6("packets", {"ipv6"}, "Count of IPv6 packets")
            , total_in("packets", {"in"}, "Count of total ingress packets")
            , total_out("packets", {"out"}, "Count of total egress packets")
        {
        }
    };
    counters _counters;

    Rate _rate_in;
    Rate _rate_out;

public:
    NetworkMetricsBucket()
        : _srcIPCard("packets", {"cardinality", "src_ips_in"}, "Source IP cardinality")
        , _dstIPCard("packets", {"cardinality", "dst_ips_out"}, "Destination IP cardinality")
        , _topGeoLoc("packets", "geo_loc", {"top_geoLoc"}, "Top GeoIP locations")
        , _topASN("packets", "asn", {"top_ASN"}, "Top ASNs by IP")
        , _topIPv4("packets", "ipv4", {"top_ipv4"}, "Top IPv4 IP addresses")
        , _topIPv6("packets", "ipv6", {"top_ipv6"}, "Top IPv6 IP addresses")
        , _rate_in("packets", {"rates", "pps_in"}, "Rate of ingress in packets per second")
        , _rate_out("packets", {"rates", "pps_out"}, "Rate of egress in packets per second")
    {
        set_event_rate_info("packets", {"rates", "pps_total"}, "Rate of all packets (combined ingress and egress) in packets per second");
        set_num_events_info("packets", {"total"}, "Total packets processed");
        set_num_sample_info("packets", {"deep_samples"}, "Total packets that were sampled for deep inspection");
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

    // must be thread safe as it is called from time window maintenance thread
    void on_set_read_only() override
    {
        // stop rate collection
        _rate_in.cancel();
        _rate_out.cancel();
    }

    void process_packet(bool deep, pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4);
    void process_dnstap(bool deep, const dnstap::Dnstap &payload);
    void process_sflow(bool deep, const SFSample &payload);
    void process_net_layer(PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4);
    void process_net_layer(PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, bool is_ipv6, pcpp::IPv4Address &ipv4_in, pcpp::IPv4Address &ipv4_out, pcpp::IPv6Address &ipv6_in, pcpp::IPv6Address &ipv6_out);
};

class NetworkMetricsManager final : public visor::AbstractMetricsManager<NetworkMetricsBucket>
{
public:
    NetworkMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<NetworkMetricsBucket>(window_config)
    {
    }

    void process_packet(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);
    void process_dnstap(const dnstap::Dnstap &payload);
    void process_sflow(const SFSample &payload);
};

class NetStreamHandler final : public visor::StreamMetricsHandler<NetworkMetricsManager>
{

    // the input stream sources we support (only one will be in use at a time)
    PcapInputStream *_pcap_stream{nullptr};
    DnstapInputStream *_dnstap_stream{nullptr};
    MockInputStream *_mock_stream{nullptr};
    SflowInputStream *_sflow_stream{nullptr};

    // the stream handlers sources we support (only one will be in use at a time)
    DnsStreamHandler *_dns_handler{nullptr};

    sigslot::connection _dnstap_connection;

    sigslot::connection _sflow_connection;

    sigslot::connection _pkt_connection;
    sigslot::connection _start_tstamp_connection;
    sigslot::connection _end_tstamp_connection;

    sigslot::connection _pkt_udp_connection;

    static const inline StreamMetricsHandler::GroupDefType _group_defs = {
        {"cardinality", group::NetMetrics::Cardinality},
        {"counters", group::NetMetrics::Counters},
        {"top_geo", group::NetMetrics::TopGeo},
        {"top_ips", group::NetMetrics::TopIps}};

    void process_sflow_cb(const SFSample &);
    void process_dnstap_cb(const dnstap::Dnstap &);
    void process_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);
    void process_udp_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp);
    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

public:
    NetStreamHandler(const std::string &name, InputStream *stream, const Configurable *window_config, StreamHandler *handler = nullptr);
    ~NetStreamHandler() override;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "packets";
    }

    size_t consumer_count() const override
    {
        return 0;
    }

    void start() override;
    void stop() override;
};

}
