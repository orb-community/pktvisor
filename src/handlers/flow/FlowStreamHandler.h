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

static constexpr const char *FLOW_SCHEMA{"flow"};

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
    std::string device_id;
    timespec stamp;
    size_t raw_size;
    uint64_t filtered;
    std::vector<FlowData> flow_data;

    FlowPacket(std::string id, timespec stamp, size_t raw_size)
        : device_id(id)
        , raw_size(raw_size)
        , stamp(stamp)
        , filtered(0)
    {
    }
};

struct FlowTopN {
    TopN<std::string> topSrcIP;
    TopN<std::string> topDstIP;
    TopN<uint16_t> topSrcPort;
    TopN<uint16_t> topDstPort;
    TopN<std::string> topSrcIPandPort;
    TopN<std::string> topDstIPandPort;
    TopN<std::string> topConversations;
    TopN<uint32_t> topInIfIndex;
    TopN<uint32_t> topOutIfIndex;
    FlowTopN(std::string metric)
        : topSrcIP(FLOW_SCHEMA, "ip", {"top_src_ips_" + metric}, "Top source IP addresses by " + metric)
        , topDstIP(FLOW_SCHEMA, "ip", {"top_dst_ips_" + metric}, "Top destination IP addresses by " + metric)
        , topSrcPort(FLOW_SCHEMA, "port", {"top_src_ports_" + metric}, "Top source ports by " + metric)
        , topDstPort(FLOW_SCHEMA, "port", {"top_dst_ports_" + metric}, "Top destination ports by " + metric)
        , topSrcIPandPort(FLOW_SCHEMA, "ip_port", {"top_src_ips_and_port_" + metric}, "Top source IP addresses and port by " + metric)
        , topDstIPandPort(FLOW_SCHEMA, "ip_port", {"top_dst_ips_and_port_" + metric}, "Top destination IP addresses and port by " + metric)
        , topConversations(FLOW_SCHEMA, "conversations", {"top_conversations_" + metric}, "Top source IP addresses and port by " + metric)
        , topInIfIndex(FLOW_SCHEMA, "index", {"top_in_if_index_" + metric}, "Top input interface indexes by " + metric)
        , topOutIfIndex(FLOW_SCHEMA, "index", {"top_out_if_index_" + metric}, "Top output interface indexes by " + metric)
    {
    }

    void set_topn_count(size_t topn_count)
    {
        topSrcIP.set_topn_count(topn_count);
        topDstIP.set_topn_count(topn_count);
        topSrcPort.set_topn_count(topn_count);
        topDstPort.set_topn_count(topn_count);
        topSrcIPandPort.set_topn_count(topn_count);
        topDstIPandPort.set_topn_count(topn_count);
        topConversations.set_topn_count(topn_count);
        topInIfIndex.set_topn_count(topn_count);
        topOutIfIndex.set_topn_count(topn_count);
    }
};

struct FlowDevice {

    struct counters {
        Counter UDP;
        Counter TCP;
        Counter OtherL4;
        Counter IPv4;
        Counter IPv6;
        Counter filtered;
        Counter total;
        counters()
            : UDP("flow", {"udp"}, "Count of UDP packets")
            , TCP("flow", {"tcp"}, "Count of TCP packets")
            , OtherL4("flow", {"other_l4"}, "Count of packets which are not UDP or TCP")
            , IPv4("flow", {"ipv4"}, "Count of IPv4 packets")
            , IPv6("flow", {"ipv6"}, "Count of IPv6 packets")
            , filtered("flow", {"filtered"}, "Count of total flows seen that did not match the configured filter(s) (if any)")
            , total("flow", {"flows"}, "Count of total flows that match the configured filter(s) (if any)")
        {
        }
    };

    counters counters;
    Quantile<std::size_t> payload_size;
    TopN<std::string> topGeoLoc;
    TopN<std::string> topASN;
    Cardinality conversationsCard;
    Cardinality srcIPCard;
    Cardinality dstIPCard;
    Cardinality srcPortCard;
    Cardinality dstPortCard;
    FlowTopN topByBytes;
    FlowTopN topByPackets;

    FlowDevice()
        : payload_size(FLOW_SCHEMA, {"payload_size"}, "Quantiles of payload sizes, in bytes")
        , topGeoLoc(FLOW_SCHEMA, "geo_loc", {"top_geoLoc"}, "Top GeoIP locations")
        , topASN(FLOW_SCHEMA, "asn", {"top_ASN"}, "Top ASNs by IP")
        , conversationsCard(FLOW_SCHEMA, {"cardinality", "conversations"}, "Conversations cardinality")
        , srcIPCard(FLOW_SCHEMA, {"cardinality", "src_ips_in"}, "Source IP cardinality")
        , dstIPCard(FLOW_SCHEMA, {"cardinality", "dst_ips_out"}, "Destination IP cardinality")
        , srcPortCard(FLOW_SCHEMA, {"cardinality", "src_ports_in"}, "Source ports cardinality")
        , dstPortCard(FLOW_SCHEMA, {"cardinality", "dst_ports_out"}, "Destination ports cardinality")
        , topByBytes("bytes")
        , topByPackets("packets")
    {
    }

    void set_topn_count(size_t topn_count)
    {
        topGeoLoc.set_topn_count(topn_count);
        topASN.set_topn_count(topn_count);
        topByBytes.set_topn_count(topn_count);
        topByPackets.set_topn_count(topn_count);
    }
};

class FlowMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;

    struct counters {
        Counter volume;
        Counter filtered;
        Counter total;
        counters()
            : volume(FLOW_SCHEMA, {"volume_bytes"}, "Count of total raw packet bytes")
            , filtered(FLOW_SCHEMA, {"filtered"}, "Count of total flows seen that did not match the configured filter(s) (if any)")
            , total(FLOW_SCHEMA, {"flows"}, "Count of total flows that match the configured filter(s) (if any)")
        {
        }
    };
    counters _counters;

    size_t _topn_count{10};
    Rate _rate;
    Rate _throughput;

    using InterfacePair = std::pair<uint32_t, uint32_t>;
    //  <DeviceId, FlowDevice>
    std::map<std::string, std::unique_ptr<FlowDevice>> _devices_metrics;

    void _process_geo_metrics(FlowDevice *device, const pcpp::IPv4Address &ipv4);
    void _process_geo_metrics(FlowDevice *device, const pcpp::IPv6Address &ipv6);

public:
    FlowMetricsBucket()
        : _rate(FLOW_SCHEMA, {"rates", "packets"}, "Rate of combined flow throughput in packets per second")
        , _throughput("payload", {"rates", "bytes"}, "Rate of combined flow throughput in bytes per second")
    {
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
        _topn_count = topn_count;
    }

    // must be thread safe as it is called from time window maintenance thread
    void on_set_read_only() override
    {
        // stop rate collection
        _rate.cancel();
        _throughput.cancel();
    }

    void process_filtered(uint64_t filtered = 1)
    {
        std::unique_lock lock(_mutex);
        _counters.filtered += filtered;
    }
    void process_flow(bool deep, const FlowPacket &payload);
};

class FlowMetricsManager final : public visor::AbstractMetricsManager<FlowMetricsBucket>
{
public:
    FlowMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<FlowMetricsBucket>(window_config)
    {
    }

    void process_filtered(timespec stamp, uint64_t filtered)
    {
        // base event, no sample
        new_event(stamp, false);
        live_bucket()->process_filtered(filtered);
    }
    void process_flow(const FlowPacket &payload);
};

class FlowStreamHandler final : public visor::StreamMetricsHandler<FlowMetricsManager>
{

    // the input stream event proxy we support (only one will be in use at a time)
    MockInputEventProxy *_mock_proxy{nullptr};
    FlowInputEventProxy *_flow_proxy{nullptr};

    sigslot::connection _sflow_connection;
    sigslot::connection _netflow_connection;
    sigslot::connection _heartbeat_connection;

    std::vector<Ipv4Subnet> _IPv4_ips_list;
    std::vector<Ipv6Subnet> _IPv6_ips_list;
    std::vector<Ipv4Subnet> _IPv4_devices_list;
    std::vector<Ipv6Subnet> _IPv6_devices_list;

    enum class ParserType {
        Port,
        Interface,
    };
    std::map<ParserType, std::vector<std::pair<uint32_t, uint32_t>>> _parsed_list;
    static const inline std::map<ParserType, std::string> _parser_types_string = {
        {ParserType::Port, "only_ports"},
        {ParserType::Interface, "only_interfaces"},
    };

    bool _sample_rate_scaling;

    enum Filters {
        OnlyIps,
        OnlyDevices,
        OnlyPorts,
        OnlyInterfaces,
        GeoLocNotFound,
        AsnNotFound,
        FiltersMAX
    };
    std::bitset<Filters::FiltersMAX> _f_enabled;

    static const inline StreamMetricsHandler::GroupDefType _group_defs = {
        {"cardinality", group::FlowMetrics::Cardinality},
        {"counters", group::FlowMetrics::Counters},
        {"top_geo", group::FlowMetrics::TopGeo},
        {"top_by_bytes", group::FlowMetrics::TopByBytes},
        {"top_by_packets", group::FlowMetrics::TopByPackets}};

    void process_sflow_cb(const SFSample &, size_t);
    void process_netflow_cb(const std::string &, const NFSample &, size_t);
    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

    void _parse_ports_or_interfaces(const std::vector<std::string> &port_interface_list, ParserType type);
    bool _match_parser(uint32_t value, ParserType type);
    void _parse_host_specs(const std::vector<std::string> &host_list, bool device = false);
    bool _match_subnet(std::vector<Ipv4Subnet> &IPv4_subnet_list, std::vector<Ipv6Subnet> &IPv6_subnet_list, uint32_t ipv4 = 0, const uint8_t *ipv6 = nullptr);
    bool _filtering(const FlowData &flow);

public:
    FlowStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config, StreamHandler *handler = nullptr);
    ~FlowStreamHandler() override;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return FLOW_SCHEMA;
    }

    size_t consumer_count() const override
    {
        return 0;
    }

    void start() override;
    void stop() override;
};
}
