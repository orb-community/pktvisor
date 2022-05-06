/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "FlowInputStream.h"
#include "MockInputStream.h"
#include "StreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <string>

namespace visor::handler::flow {

using namespace visor::input::mock;
using namespace visor::input::flow;

typedef std::pair<in_addr, uint8_t> Ipv4Subnet;
typedef std::pair<in6_addr, uint8_t> Ipv6Subnet;

namespace group {
enum FlowMetrics : visor::MetricGroupIntType {
    Counters,
    Cardinality,
    TopGeo,
    TopByPackets,
    TopByBytes
};
}

struct FlowData {
    bool is_ipv6;
    IP_PROTOCOL l4;
    size_t payload_size;
    uint32_t packets;
    pcpp::IPv4Address ipv4_in;
    pcpp::IPv4Address ipv4_out;
    pcpp::IPv6Address ipv6_in;
    pcpp::IPv6Address ipv6_out;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t if_in_index;
    uint32_t if_out_index;
};

struct FlowPacket {
    timespec stamp;
    std::vector<FlowData> flow_data;
};

class FlowMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;

    Cardinality _srcIPCard;
    Cardinality _dstIPCard;

    TopN<std::string> _topGeoLoc;
    TopN<std::string> _topASN;

    struct topns {
        TopN<std::string> topSrcIP;
        TopN<std::string> topDstIP;
        TopN<uint16_t> topSrcPort;
        TopN<uint16_t> topDstPort;
        TopN<uint32_t> topInIfIndex;
        TopN<uint32_t> topOutIfIndex;
        topns(std::string metric)
            : topSrcIP("flows", "ip", {"top_src_ip_" + metric}, "Top source IP addresses by " + metric)
            , topDstIP("flows", "ip", {"top_dst_ip_" + metric}, "Top destination IP addresses by " + metric)
            , topSrcPort("flows", "port", {"top_src_ports_" + metric}, "Top source ports by " + metric)
            , topDstPort("flows", "port", {"top_dst_ports_" + metric}, "Top destination ports by " + metric)
            , topInIfIndex("flows", "index", {"top_in_if_index_" + metric}, "Top input interface indexes  by " + metric)
            , topOutIfIndex("flows", "index", {"top_out_if_index_" + metric}, "Top output interface indexes by " + metric)
        {
        }
    };

    topns _topByBytes;
    topns _topByPackets;

    // total numPackets is tracked in base class num_events
    struct counters {
        Counter UDP;
        Counter TCP;
        Counter OtherL4;
        Counter IPv4;
        Counter IPv6;
        Counter total;
        counters()
            : UDP("flows", {"udp"}, "Count of UDP packets")
            , TCP("flows", {"tcp"}, "Count of TCP packets")
            , OtherL4("flows", {"other_l4"}, "Count of packets which are not UDP or TCP")
            , IPv4("flows", {"ipv4"}, "Count of IPv4 packets")
            , IPv6("flows", {"ipv6"}, "Count of IPv6 packets")
            , total("flows", {"flows"}, "Count of total flows")
        {
        }
    };
    counters _counters;

    Quantile<std::size_t> _payload_size;

    Rate _rate;
    Rate _throughput;

public:
    FlowMetricsBucket()
        : _srcIPCard("flows", {"cardinality", "src_ips_in"}, "Source IP cardinality")
        , _dstIPCard("flows", {"cardinality", "dst_ips_out"}, "Destination IP cardinality")
        , _topGeoLoc("flows", "geo_loc", {"top_geoLoc"}, "Top GeoIP locations")
        , _topASN("flows", "asn", {"top_ASN"}, "Top ASNs by IP")
        , _topByBytes("bytes")
        , _topByPackets("packets")
        , _payload_size("flows", {"payload_size"}, "Quantiles of payload sizes, in bytes")
        , _rate("flows", {"rates", "pps"}, "Rate of flow packets per second")
        , _throughput("payload", {"rates", "bps"}, "Rate of flow packets size in bytes per second")
    {
        set_event_rate_info("flows", {"rates", "pps_total"}, "Rate of all packets (combined ingress and egress) in packets per second");
        set_num_events_info("flows", {"total"}, "Total packets processed");
        set_num_sample_info("flows", {"deep_samples"}, "Total packets that were sampled for deep inspection");
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
        _rate.cancel();
        _throughput.cancel();
    }

    void process_sflow(bool deep, const SFSample &payload);
    void process_netflow(bool deep, const NFSample &payload);
    void process_flow(bool deep, FlowData &flow);
    // void process_flow(bool is_ipv6, IP_PROTOCOL l4, size_t payload_size, pcpp::IPv4Address &ipv4_in, pcpp::IPv4Address &ipv4_out, pcpp::IPv6Address &ipv6_in, pcpp::IPv6Address &ipv6_out);
};

class FlowMetricsManager final : public visor::AbstractMetricsManager<FlowMetricsBucket>
{
public:
    FlowMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<FlowMetricsBucket>(window_config)
    {
    }

    void process_sflow(const SFSample &payload);
    void process_netflow(const NFSample &payload);
};

class FlowStreamHandler final : public visor::StreamMetricsHandler<FlowMetricsManager>
{

    // the input stream sources we support (only one will be in use at a time)
    MockInputStream *_mock_stream{nullptr};
    FlowInputStream *_flow_stream{nullptr};

    sigslot::connection _sflow_connection;
    sigslot::connection _netflow_connection;

    std::vector<Ipv4Subnet> _IPv4_host_list;
    std::vector<Ipv6Subnet> _IPv6_host_list;

    enum Filters {
        OnlyHosts,
        FiltersMAX
    };
    std::bitset<Filters::FiltersMAX> _f_enabled;

    static const inline StreamMetricsHandler::GroupDefType _group_defs = {
        {"cardinality", group::FlowMetrics::Cardinality},
        {"counters", group::FlowMetrics::Counters},
        {"top_geo", group::FlowMetrics::TopGeo},
        {"top_by_bytes", group::FlowMetrics::TopByBytes},
        {"top_by_packets", group::FlowMetrics::TopByPackets}};

    void process_sflow_cb(const SFSample &);
    void process_netflow_cb(const NFSample &);
    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

    void _parse_host_specs(const std::vector<std::string> &host_list);
    bool _match_subnet(const std::string &flow_ip);

public:
    FlowStreamHandler(const std::string &name, InputStream *stream, const Configurable *window_config, StreamHandler *handler = nullptr);
    ~FlowStreamHandler() override;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "flows";
    }

    size_t consumer_count() const override
    {
        return 0;
    }

    void start() override;
    void stop() override;
};

}
