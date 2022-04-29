/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "FlowStreamHandler.h"
#include <Corrade/Utility/Debug.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wc99-extensions"
#pragma GCC diagnostic ignored "-Wpedantic"
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#pragma GCC diagnostic pop
#include <arpa/inet.h>
#include <cpc_union.hpp>
#include <fmt/format.h>

namespace visor::handler::flow {

FlowStreamHandler::FlowStreamHandler(const std::string &name, InputStream *stream, const Configurable *window_config, StreamHandler *handler)
    : visor::StreamMetricsHandler<FlowMetricsManager>(name, window_config)
{
    if (handler) {
        throw StreamHandlerException(fmt::format("FlowStreamHandler: unsupported upstream chained stream handler {}", handler->name()));
    }
    // figure out which input stream we have
    if (stream) {
        _mock_stream = dynamic_cast<MockInputStream *>(stream);
        _flow_stream = dynamic_cast<FlowInputStream *>(stream);
        if (!_mock_stream && !_flow_stream) {
            throw StreamHandlerException(fmt::format("FlowStreamHandler: unsupported input stream {}", stream->name()));
        }
    }
}

void FlowStreamHandler::start()
{
    if (_running) {
        return;
    }

    // default enabled groups
    _groups.set(group::FlowMetrics::Counters);
    _groups.set(group::FlowMetrics::Cardinality);

    process_groups(_group_defs);

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    if (_flow_stream) {
        _sflow_connection = _flow_stream->sflow_signal.connect(&FlowStreamHandler::process_sflow_cb, this);
        _netflow_connection = _flow_stream->netflow_signal.connect(&FlowStreamHandler::process_netflow_cb, this);
    }

    _running = true;
}

void FlowStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    if (_flow_stream) {
        _sflow_connection.disconnect();
        _netflow_connection.disconnect();
    }

    _running = false;
}

FlowStreamHandler::~FlowStreamHandler()
{
}

// callback from input module
void FlowStreamHandler::set_start_tstamp(timespec stamp)
{
    _metrics->set_start_tstamp(stamp);
}

void FlowStreamHandler::set_end_tstamp(timespec stamp)
{
    _metrics->set_end_tstamp(stamp);
}

void FlowStreamHandler::process_sflow_cb(const SFSample &payload)
{
    _metrics->process_sflow(payload);
}

void FlowStreamHandler::process_netflow_cb(const NFSample &payload)
{
    _metrics->process_netflow(payload);
}

void FlowMetricsBucket::specialized_merge(const AbstractMetricsBucket &o)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const FlowMetricsBucket &>(o);

    // rates maintain their own thread safety
    _rate_in.merge(other._rate_in);
    _rate_out.merge(other._rate_out);
    _throughput_in.merge(other._throughput_in);
    _throughput_out.merge(other._throughput_out);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    if (group_enabled(group::FlowMetrics::Counters)) {
        _counters.UDP += other._counters.UDP;
        _counters.TCP += other._counters.TCP;
        _counters.OtherL4 += other._counters.OtherL4;
        _counters.IPv4 += other._counters.IPv4;
        _counters.IPv6 += other._counters.IPv6;
        _counters.total_in += other._counters.total_in;
        _counters.total_out += other._counters.total_out;
    }

    if (group_enabled(group::FlowMetrics::Cardinality)) {
        _srcIPCard.merge(other._srcIPCard);
        _dstIPCard.merge(other._dstIPCard);
    }

    if (group_enabled(group::FlowMetrics::TopIps)) {
        _topIPv4.merge(other._topIPv4);
        _topIPv6.merge(other._topIPv6);
    }

    _topGeoLoc.merge(other._topGeoLoc);
    _topASN.merge(other._topASN);

    _payload_size.merge(other._payload_size);
}

void FlowMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{

    _rate_in.to_prometheus(out, add_labels);
    _rate_out.to_prometheus(out, add_labels);
    _throughput_in.to_prometheus(out, add_labels);
    _throughput_out.to_prometheus(out, add_labels);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_prometheus(out, add_labels);
        num_events->to_prometheus(out, add_labels);
        num_samples->to_prometheus(out, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    if (group_enabled(group::FlowMetrics::Counters)) {
        _counters.UDP.to_prometheus(out, add_labels);
        _counters.TCP.to_prometheus(out, add_labels);
        _counters.OtherL4.to_prometheus(out, add_labels);
        _counters.IPv4.to_prometheus(out, add_labels);
        _counters.IPv6.to_prometheus(out, add_labels);
        _counters.total_in.to_prometheus(out, add_labels);
        _counters.total_out.to_prometheus(out, add_labels);
    }

    if (group_enabled(group::FlowMetrics::Cardinality)) {
        _srcIPCard.to_prometheus(out, add_labels);
        _dstIPCard.to_prometheus(out, add_labels);
    }

    if (group_enabled(group::FlowMetrics::TopIps)) {
        _topIPv4.to_prometheus(out, add_labels, [](const uint32_t &val) { return pcpp::IPv4Address(val).toString(); });
        _topIPv6.to_prometheus(out, add_labels);
    }

    _topGeoLoc.to_prometheus(out, add_labels);
    _topASN.to_prometheus(out, add_labels);

    _payload_size.to_prometheus(out, add_labels);
}

void FlowMetricsBucket::to_json(json &j) const
{

    // do rates first, which handle their own locking
    bool live_rates = !read_only() && !recorded_stream();
    _rate_in.to_json(j, live_rates);
    _rate_out.to_json(j, live_rates);
    _throughput_in.to_json(j, live_rates);
    _throughput_out.to_json(j, live_rates);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_json(j, live_rates);
        num_events->to_json(j);
        num_samples->to_json(j);
    }

    std::shared_lock r_lock(_mutex);

    if (group_enabled(group::FlowMetrics::Counters)) {
        _counters.UDP.to_json(j);
        _counters.TCP.to_json(j);
        _counters.OtherL4.to_json(j);
        _counters.IPv4.to_json(j);
        _counters.IPv6.to_json(j);
        _counters.total_in.to_json(j);
        _counters.total_out.to_json(j);
    }

    if (group_enabled(group::FlowMetrics::Cardinality)) {
        _srcIPCard.to_json(j);
        _dstIPCard.to_json(j);
    }

    if (group_enabled(group::FlowMetrics::TopIps)) {
        _topIPv4.to_json(j, [](const uint32_t &val) { return pcpp::IPv4Address(val).toString(); });
        _topIPv6.to_json(j);
    }

    _topGeoLoc.to_json(j);
    _topASN.to_json(j);

    _payload_size.to_json(j);
}

void FlowMetricsBucket::process_sflow(bool deep, const SFSample &payload)
{
    for (const auto &sample : payload.elements) {
        pcpp::ProtocolType l3;
        if (sample.gotIPV4) {
            l3 = pcpp::IPv4;
        } else if (sample.gotIPV6) {
            l3 = pcpp::IPv6;
        }

        pcpp::ProtocolType l4;
        switch (sample.dcd_ipProtocol) {
        case IP_PROTOCOL::TCP:
            l4 = pcpp::TCP;
            break;
        case IP_PROTOCOL::UDP:
            l4 = pcpp::UDP;
            break;
        }

        PacketDirection dir;
        if (sample.ifCounters.ifDirection == DIRECTION::IN) {
            dir = PacketDirection::toHost;
        } else if (sample.ifCounters.ifDirection == DIRECTION::OUT) {
            dir = PacketDirection::fromHost;
        }

        if (!deep) {
            //process_net_layer(dir, l3, l4, sample.sampledPacketSize);
            return;
        }

        bool is_ipv6{false};
        pcpp::IPv4Address ipv4_in, ipv4_out;
        pcpp::IPv6Address ipv6_in, ipv6_out;

        if (sample.ipsrc.type == SFLADDRESSTYPE_IP_V4) {
            is_ipv6 = false;
            ipv4_in = pcpp::IPv4Address(sample.ipsrc.address.ip_v4.addr);

        } else if (sample.ipsrc.type == SFLADDRESSTYPE_IP_V6) {
            is_ipv6 = true;
            ipv6_in = pcpp::IPv6Address(sample.ipsrc.address.ip_v6.addr);
        }

        if (sample.ipdst.type == SFLADDRESSTYPE_IP_V4) {
            is_ipv6 = false;
            ipv4_out = pcpp::IPv4Address(sample.ipdst.address.ip_v4.addr);
        } else if (sample.ipdst.type == SFLADDRESSTYPE_IP_V6) {
            is_ipv6 = true;
            ipv6_out = pcpp::IPv6Address(sample.ipdst.address.ip_v6.addr);
        }

        //process_net_layer(dir, l3, l4, sample.sampledPacketSize, is_ipv6, ipv4_in, ipv4_out, ipv6_in, ipv6_out);
    }
}

void FlowMetricsBucket::process_netflow(bool deep, const NFSample &payload)
{
    for (const auto &sample : payload.flows) {
        pcpp::ProtocolType l3;
        if (sample.is_ipv6) {
            l3 = pcpp::IPv6;
        } else {
            l3 = pcpp::IPv4;
        }

        pcpp::ProtocolType l4;
        switch (sample.protocol) {
        case IP_PROTOCOL::TCP:
            l4 = pcpp::TCP;
            break;
        case IP_PROTOCOL::UDP:
            l4 = pcpp::UDP;
            break;
        }

        if (!deep) {
            //process_net_layer(dir, l3, l4, sample.flow_octets);
            return;
        }

        bool is_ipv6{false};
        pcpp::IPv4Address ipv4_in, ipv4_out;
        pcpp::IPv6Address ipv6_in, ipv6_out;

        if (sample.is_ipv6) {
            is_ipv6 = true;
            ipv6_in = pcpp::IPv6Address(reinterpret_cast<uint8_t *>(sample.src_ip));
            ipv6_out = pcpp::IPv6Address(reinterpret_cast<uint8_t *>(sample.dst_ip));
        } else {
            ipv4_in = pcpp::IPv4Address(sample.src_ip);
            ipv4_out = pcpp::IPv4Address(sample.dst_ip);
        }

        //process_net_layer(dir, l3, l4, sample.flow_octets, is_ipv6, ipv4_in, ipv4_out, ipv6_in, ipv6_out);
    }
}

void FlowMetricsManager::process_sflow(const SFSample &payload)
{
    timespec stamp;
    // use now()
    std::timespec_get(&stamp, TIME_UTC);
    // base event
    new_event(stamp);
    // process in the "live" bucket
    live_bucket()->process_sflow(_deep_sampling_now, payload);
}

void FlowMetricsManager::process_netflow(const NFSample &payload)
{
    timespec stamp;
    if (payload.time_sec || payload.time_nanosec) {
        stamp.tv_sec = payload.time_sec;
        stamp.tv_nsec = payload.time_nanosec;
    } else {
        // use now()
        std::timespec_get(&stamp, TIME_UTC);
    }
    // base event
    new_event(stamp);
    // process in the "live" bucket
    live_bucket()->process_netflow(_deep_sampling_now, payload);
}

}
