/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "FlowInputStream.h"
#include "MockInputStream.h"
#include "StreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <string>

namespace visor::handler::flow {

using namespace visor::input::mock;
using namespace visor::input::flow;

namespace group {
enum FlowMetrics : visor::MetricGroupIntType {
    Counters,
    Cardinality,
    TopIps
};
}

enum class PacketDirection {
    toHost,
    fromHost,
    unknown
};

class FlowMetricsBucket final : public visor::AbstractMetricsBucket
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

    Quantile<std::size_t> _payload_size;

    Rate _rate_in;
    Rate _rate_out;
    Rate _throughput_in;
    Rate _throughput_out;

public:
    FlowMetricsBucket()
        : _srcIPCard("packets", {"cardinality", "src_ips_in"}, "Source IP cardinality")
        , _dstIPCard("packets", {"cardinality", "dst_ips_out"}, "Destination IP cardinality")
        , _topGeoLoc("packets", "geo_loc", {"top_geoLoc"}, "Top GeoIP locations")
        , _topASN("packets", "asn", {"top_ASN"}, "Top ASNs by IP")
        , _topIPv4("packets", "ipv4", {"top_ipv4"}, "Top IPv4 IP addresses")
        , _topIPv6("packets", "ipv6", {"top_ipv6"}, "Top IPv6 IP addresses")
        , _payload_size("packets", {"payload_size"}, "Quantiles of payload sizes, in bytes")
        , _rate_in("packets", {"rates", "pps_in"}, "Rate of ingress in packets per second")
        , _rate_out("packets", {"rates", "pps_out"}, "Rate of egress in packets per second")
        , _throughput_in("payload", {"rates", "bps_in"}, "Rate of ingress packets size in bytes per second")
        , _throughput_out("payload", {"rates", "bps_out"}, "Rate of egress packets size in bytes per second")
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
        _throughput_in.cancel();
        _throughput_out.cancel();
    }

    void process_sflow(bool deep, const SFSample &payload);
    void process_netflow(bool deep, const NFSample &payload);
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

    static const inline StreamMetricsHandler::GroupDefType _group_defs = {
        {"cardinality", group::FlowMetrics::Cardinality},
        {"counters", group::FlowMetrics::Counters},
        {"top_ips", group::FlowMetrics::TopIps}};

    void process_sflow_cb(const SFSample &);
    void process_netflow_cb(const NFSample &);
    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

public:
    FlowStreamHandler(const std::string &name, InputStream *stream, const Configurable *window_config, StreamHandler *handler = nullptr);
    ~FlowStreamHandler() override;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "flow";
    }

    size_t consumer_count() const override
    {
        return 0;
    }

    void start() override;
    void stop() override;
};

}
