/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "FlowStreamHandler.h"
#include "GeoDB.h"
#include "utils.h"
#include <Corrade/Utility/Debug.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wc99-extensions"
#pragma GCC diagnostic ignored "-Wpedantic"
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
    _groups.set(group::FlowMetrics::TopByBytes);
    _groups.set(group::FlowMetrics::TopByPackets);

    process_groups(_group_defs);

    if (config_exists("only_hosts")) {
        _parse_host_specs(config_get<StringList>("only_hosts"));
        _f_enabled.set(Filters::OnlyHosts);
    }

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

void FlowStreamHandler::_parse_host_specs(const std::vector<std::string> &host_list)
{
    for (const auto &host : host_list) {
        auto delimiter = host.find('/');
        if (delimiter == host.npos) {
            throw StreamHandlerException(fmt::format("invalid CIDR: {}", host));
        }
        auto ip = host.substr(0, delimiter);
        auto cidr = host.substr(++delimiter);
        auto not_number = std::count_if(cidr.begin(), cidr.end(),
            [](unsigned char c) { return !std::isdigit(c); });
        if (not_number) {
            throw StreamHandlerException(fmt::format("invalid CIDR: {}", host));
        }

        auto cidr_number = std::stoi(cidr);
        if (ip.find(':') != ip.npos) {
            if (cidr_number < 0 || cidr_number > 128) {
                throw StreamHandlerException(fmt::format("invalid CIDR: {}", host));
            }
            in6_addr ipv6;
            if (inet_pton(AF_INET6, ip.c_str(), &ipv6) != 1) {
                throw StreamHandlerException(fmt::format("invalid IPv6 address: {}", ip));
            }
            _IPv6_host_list.emplace_back(ipv6, cidr_number);
        } else {
            if (cidr_number < 0 || cidr_number > 32) {
                throw StreamHandlerException(fmt::format("invalid CIDR: {}", host));
            }
            in_addr ipv4;
            if (inet_pton(AF_INET, ip.c_str(), &ipv4) != 1) {
                throw StreamHandlerException(fmt::format("invalid IPv4 address: {}", ip));
            }
            _IPv4_host_list.emplace_back(ipv4, cidr_number);
        }
    }
}

bool FlowStreamHandler::_match_subnet(const std::string &flow_ip)
{
    if (flow_ip.size() == 16 && _IPv6_host_list.size() > 0) {
        in6_addr ipv6;
        std::memcpy(&ipv6, flow_ip.c_str(), sizeof(in6_addr));
        for (const auto &net : _IPv6_host_list) {
            uint8_t prefixLength = net.second;
            auto network = net.first;
            uint8_t compareByteCount = prefixLength / 8;
            uint8_t compareBitCount = prefixLength % 8;
            bool result = false;
            if (compareByteCount > 0) {
                result = std::memcmp(&network.s6_addr, &ipv6.s6_addr, compareByteCount) == 0;
            }
            if ((result || prefixLength < 8) && compareBitCount > 0) {
                uint8_t subSubnetByte = network.s6_addr[compareByteCount] >> (8 - compareBitCount);
                uint8_t subThisByte = ipv6.s6_addr[compareByteCount] >> (8 - compareBitCount);
                result = subSubnetByte == subThisByte;
            }
            if (result) {
                return true;
            }
        }
    } else if (flow_ip.size() == 4 && _IPv4_host_list.size() > 0) {
        in_addr ipv4;
        std::memcpy(&ipv4, flow_ip.c_str(), sizeof(in_addr));
        for (const auto &net : _IPv4_host_list) {
            uint8_t cidr = net.second;
            if (cidr == 0) {
                return true;
            }
            uint32_t mask = htonl((0xFFFFFFFFu) << (32 - cidr));
            if (!((ipv4.s_addr ^ net.first.s_addr) & mask)) {
                return true;
            }
        }
    }

    return false;
}


void FlowMetricsBucket::specialized_merge(const AbstractMetricsBucket &o)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const FlowMetricsBucket &>(o);

    // rates maintain their own thread safety
    _rate.merge(other._rate);
    _throughput.merge(other._throughput);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    if (group_enabled(group::FlowMetrics::Counters)) {
        _counters.UDP += other._counters.UDP;
        _counters.TCP += other._counters.TCP;
        _counters.OtherL4 += other._counters.OtherL4;
        _counters.IPv4 += other._counters.IPv4;
        _counters.IPv6 += other._counters.IPv6;
        _counters.total += other._counters.total;
    }

    if (group_enabled(group::FlowMetrics::Cardinality)) {
        _srcIPCard.merge(other._srcIPCard);
        _dstIPCard.merge(other._dstIPCard);
    }

    if (group_enabled(group::FlowMetrics::TopByBytes)) {
        _topByBytes.topSrcIP.merge(other._topByBytes.topSrcIP);
        _topByBytes.topDstIP.merge(other._topByBytes.topDstIP);
        _topByBytes.topSrcPort.merge(other._topByBytes.topSrcPort);
        _topByBytes.topDstPort.merge(other._topByBytes.topDstPort);
        _topByBytes.topInIfIndex.merge(other._topByBytes.topInIfIndex);
        _topByBytes.topOutIfIndex.merge(other._topByBytes.topOutIfIndex);
    }

    if (group_enabled(group::FlowMetrics::TopByPackets)) {
        _topByPackets.topSrcIP.merge(other._topByPackets.topSrcIP);
        _topByPackets.topDstIP.merge(other._topByPackets.topDstIP);
        _topByPackets.topSrcPort.merge(other._topByPackets.topSrcPort);
        _topByPackets.topDstPort.merge(other._topByPackets.topDstPort);
        _topByPackets.topInIfIndex.merge(other._topByPackets.topInIfIndex);
        _topByPackets.topOutIfIndex.merge(other._topByPackets.topOutIfIndex);
    }

    if (group_enabled(group::FlowMetrics::TopGeo)) {
        _topGeoLoc.merge(other._topGeoLoc);
        _topASN.merge(other._topASN);
    }

    _payload_size.merge(other._payload_size);
}

void FlowMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{

    _rate.to_prometheus(out, add_labels);
    _throughput.to_prometheus(out, add_labels);

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
        _counters.total.to_prometheus(out, add_labels);
    }

    if (group_enabled(group::FlowMetrics::Cardinality)) {
        _srcIPCard.to_prometheus(out, add_labels);
        _dstIPCard.to_prometheus(out, add_labels);
    }

    if (group_enabled(group::FlowMetrics::TopByBytes)) {
        _topByBytes.topSrcIP.to_prometheus(out, add_labels);
        _topByBytes.topDstIP.to_prometheus(out, add_labels);
        _topByBytes.topSrcPort.to_prometheus(out, add_labels);
        _topByBytes.topDstPort.to_prometheus(out, add_labels);
        _topByBytes.topInIfIndex.to_prometheus(out, add_labels);
        _topByBytes.topOutIfIndex.to_prometheus(out, add_labels);
    }

    if (group_enabled(group::FlowMetrics::TopByPackets)) {
        _topByPackets.topSrcIP.to_prometheus(out, add_labels);
        _topByPackets.topDstIP.to_prometheus(out, add_labels);
        _topByPackets.topSrcPort.to_prometheus(out, add_labels);
        _topByPackets.topDstPort.to_prometheus(out, add_labels);
        _topByPackets.topInIfIndex.to_prometheus(out, add_labels);
        _topByPackets.topOutIfIndex.to_prometheus(out, add_labels);
    }

    if (group_enabled(group::FlowMetrics::TopGeo)) {
        _topGeoLoc.to_prometheus(out, add_labels);
        _topASN.to_prometheus(out, add_labels);
    }

    _payload_size.to_prometheus(out, add_labels);
}

void FlowMetricsBucket::to_json(json &j) const
{

    // do rates first, which handle their own locking
    bool live_rates = !read_only() && !recorded_stream();
    _rate.to_json(j, live_rates);
    _throughput.to_json(j, live_rates);

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
        _counters.total.to_json(j);
    }

    if (group_enabled(group::FlowMetrics::Cardinality)) {
        _srcIPCard.to_json(j);
        _dstIPCard.to_json(j);
    }

    if (group_enabled(group::FlowMetrics::TopByBytes)) {
        _topByBytes.topSrcIP.to_json(j);
        _topByBytes.topDstIP.to_json(j);
        _topByBytes.topSrcPort.to_json(j);
        _topByBytes.topDstPort.to_json(j);
        _topByBytes.topInIfIndex.to_json(j);
        _topByBytes.topOutIfIndex.to_json(j);
    }

    if (group_enabled(group::FlowMetrics::TopByPackets)) {
        _topByPackets.topSrcIP.to_json(j);
        _topByPackets.topDstIP.to_json(j);
        _topByPackets.topSrcPort.to_json(j);
        _topByPackets.topDstPort.to_json(j);
        _topByPackets.topInIfIndex.to_json(j);
        _topByPackets.topOutIfIndex.to_json(j);
    }

    if (group_enabled(group::FlowMetrics::TopGeo)) {
        _topGeoLoc.to_json(j);
        _topASN.to_json(j);
    }

    _payload_size.to_json(j);
}

void FlowMetricsBucket::process_sflow(bool deep, const SFSample &payload)
{
    for (const auto &sample : payload.elements) {

        if (sample.sampleType == SFLCOUNTERS_SAMPLE || sample.sampleType == SFLCOUNTERS_SAMPLE_EXPANDED) {
            //skip counter flows
            continue;
        }

        FlowData flow = {};
        pcpp::ProtocolType l3;
        if (sample.gotIPV6) {
            flow.is_ipv6 = true;
        }

        flow.l4 = IP_PROTOCOL::UNKNOWN_IP;
        switch (sample.dcd_ipProtocol) {
        case IP_PROTOCOL::TCP:
            flow.l4 = IP_PROTOCOL::TCP;
            break;
        case IP_PROTOCOL::UDP:
            flow.l4 = IP_PROTOCOL::UDP;
            break;
        }

        flow.packets = 1;
        flow.payload_size = sample.sampledPacketSize;

        if (!deep) {
            process_flow(deep, flow);
            return;
        }

        flow.src_port = sample.dcd_sport;
        flow.dst_port = sample.dcd_dport;
        flow.if_in_index = sample.inputPort;
        flow.if_out_index = sample.outputPort;

        if (sample.ipsrc.type == SFLADDRESSTYPE_IP_V4) {
            flow.is_ipv6 = false;
            flow.ipv4_in = pcpp::IPv4Address(sample.ipsrc.address.ip_v4.addr);

        } else if (sample.ipsrc.type == SFLADDRESSTYPE_IP_V6) {
            flow.is_ipv6 = true;
            flow.ipv6_in = pcpp::IPv6Address(sample.ipsrc.address.ip_v6.addr);
        }

        if (sample.ipdst.type == SFLADDRESSTYPE_IP_V4) {
            flow.is_ipv6 = false;
            flow.ipv4_out = pcpp::IPv4Address(sample.ipdst.address.ip_v4.addr);
        } else if (sample.ipdst.type == SFLADDRESSTYPE_IP_V6) {
            flow.is_ipv6 = true;
            flow.ipv6_out = pcpp::IPv6Address(sample.ipdst.address.ip_v6.addr);
        }

        process_flow(deep, flow);
    }
}

void FlowMetricsBucket::process_netflow(bool deep, const NFSample &payload)
{
    for (const auto &sample : payload.flows) {
        FlowData flow = {};
        if (sample.is_ipv6) {
            flow.is_ipv6 = true;
        }

        flow.l4 = IP_PROTOCOL::UNKNOWN_IP;
        switch (sample.protocol) {
        case IP_PROTOCOL::TCP:
            flow.l4 = IP_PROTOCOL::TCP;
            break;
        case IP_PROTOCOL::UDP:
            flow.l4 = IP_PROTOCOL::UDP;
            break;
        }

        flow.packets = sample.flow_packets;
        flow.payload_size = sample.flow_octets;

        if (!deep) {
            process_flow(deep, flow);
            return;
        }

        flow.src_port = sample.src_port;
        flow.dst_port = sample.dst_port;
        flow.if_out_index = sample.if_index_out;
        flow.if_in_index = sample.if_index_in;

        if (sample.is_ipv6) {
            flow.ipv6_in = pcpp::IPv6Address(reinterpret_cast<uint8_t *>(sample.src_ip));
            flow.ipv6_out = pcpp::IPv6Address(reinterpret_cast<uint8_t *>(sample.dst_ip));
        } else {
            flow.ipv4_in = pcpp::IPv4Address(sample.src_ip);
            flow.ipv4_out = pcpp::IPv4Address(sample.dst_ip);
        }

        process_flow(deep, flow);
    }
}

void FlowMetricsBucket::process_flow(bool deep, FlowData &flow)
{
    std::unique_lock lock(_mutex);
    _rate += flow.packets;
    _throughput += flow.payload_size;

    if (group_enabled(group::FlowMetrics::Counters)) {
        ++_counters.total;

        if (flow.is_ipv6) {
            ++_counters.IPv6;
        } else {
            ++_counters.IPv4;
        }

        switch (flow.l4) {
        case IP_PROTOCOL::UDP:
            ++_counters.UDP;
            break;
        case IP_PROTOCOL::TCP:
            ++_counters.TCP;
            break;
        default:
            ++_counters.OtherL4;
            break;
        }
    }

    _payload_size.update(flow.payload_size);

    if (!deep) {
        return;
    }

    if (group_enabled(group::FlowMetrics::TopByBytes)) {
        (flow.src_port > 0) ? _topByBytes.topSrcPort.update(flow.src_port, flow.payload_size) : void();
        (flow.dst_port > 0) ? _topByBytes.topDstPort.update(flow.dst_port, flow.payload_size) : void();
        (flow.if_out_index > 0) ? _topByBytes.topInIfIndex.update(flow.if_in_index, flow.payload_size) : void();
        (flow.if_in_index > 0) ? _topByBytes.topOutIfIndex.update(flow.if_out_index, flow.payload_size) : void();
    }

    if (group_enabled(group::FlowMetrics::TopByPackets)) {
        (flow.src_port > 0) ? _topByPackets.topSrcPort.update(flow.src_port, flow.packets) : void();
        (flow.dst_port > 0) ? _topByPackets.topDstPort.update(flow.dst_port, flow.packets) : void();
        (flow.if_out_index > 0) ? _topByPackets.topInIfIndex.update(flow.if_in_index, flow.packets) : void();
        (flow.if_in_index > 0) ? _topByPackets.topOutIfIndex.update(flow.if_out_index, flow.packets) : void();
    }

    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;

    if (!flow.is_ipv6 && flow.ipv4_in.isValid()) {
        group_enabled(group::FlowMetrics::Cardinality) ? _srcIPCard.update(flow.ipv4_in.toInt()) : void();
        group_enabled(group::FlowMetrics::TopByBytes) ? _topByBytes.topSrcIP.update(flow.ipv4_in.toString(), flow.payload_size) : void();
        group_enabled(group::FlowMetrics::TopByPackets) ? _topByPackets.topSrcIP.update(flow.ipv4_in.toString(), flow.packets) : void();
        if (geo::enabled() && group_enabled(group::FlowMetrics::TopGeo)) {
            if (IPv4_to_sockaddr(flow.ipv4_in, &sa4)) {
                if (geo::GeoIP().enabled()) {
                    _topGeoLoc.update(geo::GeoIP().getGeoLocString(reinterpret_cast<struct sockaddr *>(&sa4)));
                }
                if (geo::GeoASN().enabled()) {
                    _topASN.update(geo::GeoASN().getASNString(reinterpret_cast<struct sockaddr *>(&sa4)));
                }
            }
        }
    } else if (flow.is_ipv6 && flow.ipv6_in.isValid()) {
        group_enabled(group::FlowMetrics::Cardinality) ? _srcIPCard.update(reinterpret_cast<const void *>(flow.ipv6_in.toBytes()), 16) : void();
        group_enabled(group::FlowMetrics::TopByBytes) ? _topByBytes.topSrcIP.update(flow.ipv6_in.toString(), flow.payload_size) : void();
        group_enabled(group::FlowMetrics::TopByPackets) ? _topByPackets.topSrcIP.update(flow.ipv6_in.toString(), flow.packets) : void();
        if (geo::enabled() && group_enabled(group::FlowMetrics::TopGeo)) {
            if (IPv6_to_sockaddr(flow.ipv6_in, &sa6)) {
                if (geo::GeoIP().enabled()) {
                    _topGeoLoc.update(geo::GeoIP().getGeoLocString(reinterpret_cast<struct sockaddr *>(&sa6)));
                }
                if (geo::GeoASN().enabled()) {
                    _topASN.update(geo::GeoASN().getASNString(reinterpret_cast<struct sockaddr *>(&sa6)));
                }
            }
        }
    }

    if (!flow.is_ipv6 && flow.ipv4_out.isValid()) {
        group_enabled(group::FlowMetrics::Cardinality) ? _dstIPCard.update(flow.ipv4_out.toInt()) : void();
        group_enabled(group::FlowMetrics::TopByBytes) ? _topByBytes.topDstIP.update(flow.ipv4_out.toString(), flow.payload_size) : void();
        group_enabled(group::FlowMetrics::TopByPackets) ? _topByPackets.topDstIP.update(flow.ipv4_out.toString(), flow.packets) : void();
        if (geo::enabled() && group_enabled(group::FlowMetrics::TopGeo)) {
            if (IPv4_to_sockaddr(flow.ipv4_out, &sa4)) {
                if (geo::GeoIP().enabled()) {
                    _topGeoLoc.update(geo::GeoIP().getGeoLocString(reinterpret_cast<struct sockaddr *>(&sa4)));
                }
                if (geo::GeoASN().enabled()) {
                    _topASN.update(geo::GeoASN().getASNString(reinterpret_cast<struct sockaddr *>(&sa4)));
                }
            }
        }
    } else if (flow.is_ipv6 && flow.ipv6_out.isValid()) {
        group_enabled(group::FlowMetrics::Cardinality) ? _dstIPCard.update(reinterpret_cast<const void *>(flow.ipv6_out.toBytes()), 16) : void();
        group_enabled(group::FlowMetrics::TopByBytes) ? _topByBytes.topDstIP.update(flow.ipv6_out.toString(), flow.payload_size) : void();
        group_enabled(group::FlowMetrics::TopByPackets) ? _topByPackets.topDstIP.update(flow.ipv6_out.toString(), flow.packets) : void();
        if (geo::enabled() && group_enabled(group::FlowMetrics::TopGeo)) {
            if (IPv6_to_sockaddr(flow.ipv6_out, &sa6)) {
                if (geo::GeoIP().enabled()) {
                    _topGeoLoc.update(geo::GeoIP().getGeoLocString(reinterpret_cast<struct sockaddr *>(&sa6)));
                }
                if (geo::GeoASN().enabled()) {
                    _topASN.update(geo::GeoASN().getASNString(reinterpret_cast<struct sockaddr *>(&sa6)));
                }
            }
        }
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
