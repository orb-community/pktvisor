/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "FlowInputStream.h"
#include "GeoDB.h"
#include "IpPort.h"
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
    ByPackets,
    ByBytes,
    Cardinality,
    Conversations,
    Counters,
    TopPorts,
    TopIPs,
    TopIPPorts,
    TopGeo,
    TopInterfaces
};
}

struct InterfaceEnrich {
    std::string name;
    std::string descr;
};

struct DeviceEnrich {
    std::string name;
    std::unordered_map<uint32_t, InterfaceEnrich> interfaces;
};

typedef std::unordered_map<std::string, DeviceEnrich> EnrichMap;

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
    uint64_t filtered;
    std::vector<FlowData> flow_data;

    FlowPacket(std::string id, timespec stamp)
        : device_id(id)
        , stamp(stamp)
        , filtered(0)
    {
    }
};

struct FlowTopN {
    TopN<std::string> topInSrcIP;
    TopN<std::string> topInDstIP;
    TopN<std::string> topOutSrcIP;
    TopN<std::string> topOutDstIP;
    TopN<network::IpPort> topInSrcPort;
    TopN<network::IpPort> topInDstPort;
    TopN<network::IpPort> topOutSrcPort;
    TopN<network::IpPort> topOutDstPort;
    TopN<std::string> topInSrcIPandPort;
    TopN<std::string> topInDstIPandPort;
    TopN<std::string> topOutSrcIPandPort;
    TopN<std::string> topOutDstIPandPort;
    TopN<std::string> topConversations;

    TopN<visor::geo::City> topGeoLoc;
    TopN<std::string> topASN;
    FlowTopN(std::string metric)
        : topInSrcIP(FLOW_SCHEMA, "ip", {"top_in_src_ips_" + metric}, "Top in source IP addresses by " + metric)
        , topInDstIP(FLOW_SCHEMA, "ip", {"top_in_dst_ips_" + metric}, "Top in destination IP addresses by " + metric)
        , topOutSrcIP(FLOW_SCHEMA, "ip", {"top_out_src_ips_" + metric}, "Top out source IP addresses by " + metric)
        , topOutDstIP(FLOW_SCHEMA, "ip", {"top_out_dst_ips_" + metric}, "Top out destination IP addresses by " + metric)
        , topInSrcPort(FLOW_SCHEMA, "port", {"top_in_src_ports_" + metric}, "Top in source ports by " + metric)
        , topInDstPort(FLOW_SCHEMA, "port", {"top_in_dst_ports_" + metric}, "Top in destination ports by " + metric)
        , topOutSrcPort(FLOW_SCHEMA, "port", {"top_out_src_ports_" + metric}, "Top out source ports by " + metric)
        , topOutDstPort(FLOW_SCHEMA, "port", {"top_out_dst_ports_" + metric}, "Top out destination ports by " + metric)
        , topInSrcIPandPort(FLOW_SCHEMA, "ip_port", {"top_in_src_ips_and_port_" + metric}, "Top in source IP addresses and port by " + metric)
        , topInDstIPandPort(FLOW_SCHEMA, "ip_port", {"top_in_dst_ips_and_port_" + metric}, "Top in destination IP addresses and port by " + metric)
        , topOutSrcIPandPort(FLOW_SCHEMA, "ip_port", {"top_out_src_ips_and_port_" + metric}, "Top out source IP addresses and port by " + metric)
        , topOutDstIPandPort(FLOW_SCHEMA, "ip_port", {"top_out_dst_ips_and_port_" + metric}, "Top out destination IP addresses and port by " + metric)
        , topConversations(FLOW_SCHEMA, "conversations", {"top_conversations_" + metric}, "Top source IP addresses and port by " + metric)
        , topGeoLoc(FLOW_SCHEMA, "geo_loc", {"top_geoLoc_" + metric}, "Top GeoIP locations by " + metric)
        , topASN(FLOW_SCHEMA, "asn", {"top_ASN_" + metric}, "Top ASNs by IP by " + metric)
    {
    }

    void set_settings(size_t topn_count, uint64_t percentile_threshold)
    {
        topInSrcIP.set_settings(topn_count, percentile_threshold);
        topInDstIP.set_settings(topn_count, percentile_threshold);
        topOutSrcIP.set_settings(topn_count, percentile_threshold);
        topOutDstIP.set_settings(topn_count, percentile_threshold);
        topInSrcPort.set_settings(topn_count, percentile_threshold);
        topInDstPort.set_settings(topn_count, percentile_threshold);
        topOutSrcPort.set_settings(topn_count, percentile_threshold);
        topOutDstPort.set_settings(topn_count, percentile_threshold);
        topInSrcIPandPort.set_settings(topn_count, percentile_threshold);
        topInDstIPandPort.set_settings(topn_count, percentile_threshold);
        topOutSrcIPandPort.set_settings(topn_count, percentile_threshold);
        topOutDstIPandPort.set_settings(topn_count, percentile_threshold);
        topConversations.set_settings(topn_count, percentile_threshold);
        topGeoLoc.set_settings(topn_count, percentile_threshold);
        topASN.set_settings(topn_count, percentile_threshold);
    }
};

struct Counters {
    Counter UDP;
    Counter TCP;
    Counter OtherL4;
    Counter IPv4;
    Counter IPv6;
    Counter total;
    Counters(std::string direction, std::string metric)
        : UDP(FLOW_SCHEMA, {direction + "_udp_" + metric}, "Count of " + direction + " UDP by " + metric)
        , TCP(FLOW_SCHEMA, {direction + "_tcp_" + metric}, "Count of " + direction + " TCP by " + metric)
        , OtherL4(FLOW_SCHEMA, {direction + "_other_l4_" + metric}, "Count of " + direction + " " + metric + " which are not UDP or TCP")
        , IPv4(FLOW_SCHEMA, {direction + "_ipv4_" + metric}, "Count of " + direction + " IPv4 by " + metric)
        , IPv6(FLOW_SCHEMA, {direction + "_ipv6_" + metric}, "Count of " + direction + " IPv6 by " + metric)
        , total(FLOW_SCHEMA, {direction + "_" + metric}, "Count of total " + direction + " flows by " + metric)
    {
    }
};

struct FlowInterface {

    Cardinality conversationsCard;
    Cardinality srcIPCard;
    Cardinality dstIPCard;
    Cardinality srcPortCard;
    Cardinality dstPortCard;
    FlowTopN topByBytes;
    FlowTopN topByPackets;
    Counters countersInByBytes;
    Counters countersOutByBytes;
    Counters countersInByPackets;
    Counters countersOutByPackets;

    FlowInterface()
        : conversationsCard(FLOW_SCHEMA, {"cardinality", "conversations"}, "Conversations cardinality")
        , srcIPCard(FLOW_SCHEMA, {"cardinality", "src_ips_in"}, "Source IP cardinality")
        , dstIPCard(FLOW_SCHEMA, {"cardinality", "dst_ips_out"}, "Destination IP cardinality")
        , srcPortCard(FLOW_SCHEMA, {"cardinality", "src_ports_in"}, "Source ports cardinality")
        , dstPortCard(FLOW_SCHEMA, {"cardinality", "dst_ports_out"}, "Destination ports cardinality")
        , topByBytes("bytes")
        , topByPackets("packets")
        , countersInByBytes("in", "bytes")
        , countersOutByBytes("out", "bytes")
        , countersInByPackets("in", "packets")
        , countersOutByPackets("out", "packets")
    {
    }

    void set_topn_settings(size_t topn_count, uint64_t percentile_threshold)
    {
        topByBytes.set_settings(topn_count, percentile_threshold);
        topByPackets.set_settings(topn_count, percentile_threshold);
    }
};

struct FlowDevice {

    Counter total;
    Counter filtered;

    TopN<uint32_t> topInIfIndexBytes;
    TopN<uint32_t> topOutIfIndexBytes;
    TopN<uint32_t> topInIfIndexPackets;
    TopN<uint32_t> topOutIfIndexPackets;

    std::map<uint32_t, std::unique_ptr<FlowInterface>> interfaces;

    FlowDevice()
        : total(FLOW_SCHEMA, {"records_flows"}, "Count of total flows records that match the configured filter(s) (if any)")
        , filtered(FLOW_SCHEMA, {"records_filtered"}, "Count of total flows records seen that did not match the configured filter(s) (if any)")
        , topInIfIndexBytes(FLOW_SCHEMA, "interface", {"top_in_interfaces_bytes"}, "Top input interfaces by bytes")
        , topOutIfIndexBytes(FLOW_SCHEMA, "interface", {"top_out_interfaces_bytes"}, "Top output interfaces by bytes")
        , topInIfIndexPackets(FLOW_SCHEMA, "interface", {"top_in_interfaces_packets"}, "Top input interfaces by packets")
        , topOutIfIndexPackets(FLOW_SCHEMA, "interface", {"top_out_interfaces_packets"}, "Top output interfaces by packets")
    {
    }

    void set_topn_settings(size_t topn_count, uint64_t percentile_threshold)
    {
        topInIfIndexBytes.set_settings(topn_count, percentile_threshold);
        topOutIfIndexBytes.set_settings(topn_count, percentile_threshold);
        topInIfIndexPackets.set_settings(topn_count, percentile_threshold);
        topOutIfIndexPackets.set_settings(topn_count, percentile_threshold);
    }
};

class FlowMetricsBucket final : public visor::AbstractMetricsBucket
{
protected:
    mutable std::shared_mutex _mutex;
    EnrichMap *_enrich_data{nullptr};
    size_t _topn_count{10};
    uint64_t _topn_percentile_threshold{0};
    //  <DeviceId, FlowDevice>
    std::map<std::string, std::unique_ptr<FlowDevice>> _devices_metrics;

    void _process_geo_metrics(FlowInterface *interface, const pcpp::IPv4Address &ipv4, size_t payload_size, uint32_t packets);
    void _process_geo_metrics(FlowInterface *interface, const pcpp::IPv6Address &ipv6, size_t payload_size, uint32_t packets);

public:
    FlowMetricsBucket()
    {
    }

    // visor::AbstractMetricsBucket
    void specialized_merge(const AbstractMetricsBucket &other, Metric::Aggregate agg_operator) override;
    void to_json(json &j) const override;
    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override;
    void update_topn_metrics(size_t topn_count, uint64_t percentile_threshold) override
    {
        _topn_count = topn_count;
        _topn_percentile_threshold = percentile_threshold;
    }

    inline void set_enrich_data(EnrichMap *enrich_data)
    {
        _enrich_data = enrich_data;
    }

    inline void process_filtered(uint64_t filtered, const std::string &device)
    {
        std::unique_lock lock(_mutex);
        if (!_devices_metrics.count(device)) {
            _devices_metrics[device] = std::make_unique<FlowDevice>();
            _devices_metrics[device]->set_topn_settings(_topn_count, _topn_percentile_threshold);
        }
        _devices_metrics[device]->filtered += filtered;
    }
    void process_flow(bool deep, const FlowPacket &payload);
};

class FlowMetricsManager final : public visor::AbstractMetricsManager<FlowMetricsBucket>
{
    EnrichMap _enrich_data;

public:
    FlowMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<FlowMetricsBucket>(window_config)
    {
    }

    inline void set_enrich_data(EnrichMap enrich_data)
    {
        _enrich_data = enrich_data;
        if (!_enrich_data.empty()) {
            live_bucket()->set_enrich_data(&_enrich_data);
        }
    }

    inline void process_filtered(timespec stamp, uint64_t filtered, const std::string &device)
    {
        // base event, no sample
        new_event(stamp, false);
        live_bucket()->process_filtered(filtered, device);
    }
    void process_flow(const FlowPacket &payload);

    void on_period_shift([[maybe_unused]] timespec stamp, [[maybe_unused]] const FlowMetricsBucket *maybe_expiring_bucket) override
    {
        if (!_enrich_data.empty()) {
            live_bucket()->set_enrich_data(&_enrich_data);
        }
    }
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

    std::vector<pcpp::IPv4Address> _IPv4_devices_list;
    std::vector<pcpp::IPv6Address> _IPv6_devices_list;

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
        {"bytes", group::FlowMetrics::ByBytes},
        {"packets", group::FlowMetrics::ByPackets},
        {"cardinality", group::FlowMetrics::Cardinality},
        {"conversations", group::FlowMetrics::Conversations},
        {"counters", group::FlowMetrics::Counters},
        {"top_ports", group::FlowMetrics::TopPorts},
        {"top_ips_ports", group::FlowMetrics::TopIPPorts},
        {"top_geo", group::FlowMetrics::TopGeo},
        {"top_interfaces", group::FlowMetrics::TopInterfaces}};

    void process_sflow_cb(const SFSample &, size_t);
    void process_netflow_cb(const std::string &, const NFSample &, size_t);
    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

    void _parse_ports_or_interfaces(const std::vector<std::string> &port_interface_list, ParserType type);
    bool _match_parser(uint32_t value, ParserType type);
    void _parse_host_specs(const std::vector<std::string> &host_list);
    void _parse_devices_ips(const std::vector<std::string> &device_list);
    bool _match_subnet(uint32_t ipv4 = 0, const uint8_t *ipv6 = nullptr);
    bool _filtering(const FlowData &flow);

public:
    FlowStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config);
    ~FlowStreamHandler() override;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return FLOW_SCHEMA;
    }

    void start() override;
    void stop() override;
};
}
