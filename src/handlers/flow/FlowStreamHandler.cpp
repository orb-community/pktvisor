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

FlowStreamHandler::FlowStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config, StreamHandler *handler)
    : visor::StreamMetricsHandler<FlowMetricsManager>(name, window_config)
    , _sample_rate_scaling(true)
{
    if (handler) {
        throw StreamHandlerException(fmt::format("FlowStreamHandler: unsupported upstream chained stream handler {}", handler->name()));
    }
    // figure out which input event proxy we have
    if (proxy) {
        _mock_proxy = dynamic_cast<MockInputEventProxy *>(proxy);
        _flow_proxy = dynamic_cast<FlowInputEventProxy *>(proxy);
        if (!_mock_proxy && !_flow_proxy) {
            throw StreamHandlerException(fmt::format("FlowStreamHandler: unsupported input event proxy {}", proxy->name()));
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

    // Setup Filters
    if (config_exists("only_ips")) {
        _parse_host_specs(config_get<StringList>("only_ips"));
        _f_enabled.set(Filters::OnlyIps);
    }

    if (config_exists("only_devices")) {
        _parse_host_specs(config_get<StringList>("only_devices"), true);
        _f_enabled.set(Filters::OnlyDevices);
    }

    if (config_exists("only_ports")) {
        _parse_ports_or_interfaces(config_get<StringList>("only_ports"), ParserType::Port);
        _f_enabled.set(Filters::OnlyPorts);
    }

    if (config_exists("only_interfaces")) {
        _parse_ports_or_interfaces(config_get<StringList>("only_interfaces"), ParserType::Interface);
        _f_enabled.set(Filters::OnlyInterfaces);
    }

    if (config_exists("geoloc_notfound") && config_get<bool>("geoloc_notfound")) {
        _f_enabled.set(Filters::GeoLocNotFound);
    }

    if (config_exists("asn_notfound") && config_get<bool>("asn_notfound")) {
        _f_enabled.set(Filters::AsnNotFound);
    }

    if (config_exists("sample_rate_scaling") && !config_get<bool>("sample_rate_scaling")) {
        _sample_rate_scaling = false;
    }

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    if (_flow_proxy) {
        _sflow_connection = _flow_proxy->sflow_signal.connect(&FlowStreamHandler::process_sflow_cb, this);
        _netflow_connection = _flow_proxy->netflow_signal.connect(&FlowStreamHandler::process_netflow_cb, this);
        _heartbeat_connection = _flow_proxy->heartbeat_signal.connect(&FlowStreamHandler::check_period_shift, this);
    }

    _running = true;
}

void FlowStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    if (_flow_proxy) {
        _sflow_connection.disconnect();
        _netflow_connection.disconnect();
        _heartbeat_connection.disconnect();
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

void FlowStreamHandler::process_sflow_cb(const SFSample &payload, size_t rawSize)
{
    timespec stamp;
    // use now()
    std::timespec_get(&stamp, TIME_UTC);

    std::string agentId;
    if (payload.agent_addr.type == SFLADDRESSTYPE_IP_V4) {
        agentId = pcpp::IPv4Address(payload.agent_addr.address.ip_v4.addr).toString();
    } else if (payload.agent_addr.type == SFLADDRESSTYPE_IP_V6) {
        agentId = pcpp::IPv6Address(payload.agent_addr.address.ip_v6.addr).toString();
    }

    FlowPacket packet(agentId, stamp, rawSize);

    if (_f_enabled[Filters::OnlyDevices]) {
        if (auto ipv4 = pcpp::IPv4Address(packet.device_id); ipv4.isValid()
            && !_match_subnet(_IPv4_devices_list, _IPv6_devices_list, ipv4.toInt())) {
            _metrics->process_filtered(stamp, payload.elements.size(), rawSize);
            return;
        } else if (auto ipv6 = pcpp::IPv6Address(packet.device_id); ipv6.isValid()
                   && !_match_subnet(_IPv4_devices_list, _IPv6_devices_list, 0, ipv6.toBytes())) {
            _metrics->process_filtered(stamp, payload.elements.size(), rawSize);
            return;
        }
    }

    for (const auto &sample : payload.elements) {

        if (sample.sampleType == SFLCOUNTERS_SAMPLE || sample.sampleType == SFLCOUNTERS_SAMPLE_EXPANDED) {
            // skip counter flows
            continue;
        }

        FlowData flow = {};
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

        if (_sample_rate_scaling) {
            flow.packets = sample.meanSkipCount;
            flow.payload_size = static_cast<size_t>(sample.meanSkipCount) * sample.sampledPacketSize;
        } else {
            flow.packets = 1;
            flow.payload_size = sample.sampledPacketSize;
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

        if (!_filtering(flow)) {
            packet.flow_data.push_back(flow);
        } else {
            ++packet.filtered;
        }
    }
    _metrics->process_flow(packet);
}

void FlowStreamHandler::process_netflow_cb(const std::string &senderIP, const NFSample &payload, size_t rawSize)
{
    timespec stamp;
    if (payload.time_sec || payload.time_nanosec) {
        stamp.tv_sec = payload.time_sec;
        stamp.tv_nsec = payload.time_nanosec;
    } else {
        // use now()
        std::timespec_get(&stamp, TIME_UTC);
    }
    FlowPacket packet(senderIP, stamp, rawSize);

    if (_f_enabled[Filters::OnlyDevices]) {
        if (auto ipv4 = pcpp::IPv4Address(packet.device_id); ipv4.isValid()
            && !_match_subnet(_IPv4_devices_list, _IPv6_devices_list, ipv4.toInt())) {
            _metrics->process_filtered(stamp, payload.flows.size(), rawSize);
            return;
        } else if (auto ipv6 = pcpp::IPv6Address(packet.device_id); ipv6.isValid()
                   && !_match_subnet(_IPv4_devices_list, _IPv6_devices_list, 0, ipv6.toBytes())) {
            _metrics->process_filtered(stamp, payload.flows.size(), rawSize);
            return;
        }
    }

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

        if (!_filtering(flow)) {
            packet.flow_data.push_back(flow);
        } else {
            ++packet.filtered;
        }
    }

    _metrics->process_flow(packet);
}

bool FlowStreamHandler::_filtering(const FlowData &flow)
{
    if (_f_enabled[Filters::OnlyIps]) {
        if (flow.is_ipv6 && !_match_subnet(_IPv4_ips_list, _IPv6_devices_list, 0, flow.ipv6_in.toBytes())
            && !_match_subnet(_IPv4_ips_list, _IPv6_devices_list, 0, flow.ipv6_out.toBytes())) {
            return true;
        } else if (!_match_subnet(_IPv4_ips_list, _IPv6_devices_list, flow.ipv4_in.toInt())
            && !_match_subnet(_IPv4_ips_list, _IPv6_devices_list, flow.ipv4_out.toInt())) {
            return true;
        }
    }
    if (_f_enabled[Filters::OnlyPorts] && !_match_parser(flow.src_port, ParserType::Port)
        && !_match_parser(flow.dst_port, ParserType::Port)) {
        return true;
    }
    if (_f_enabled[Filters::OnlyInterfaces] && !_match_parser(flow.if_in_index, ParserType::Interface)
        && !_match_parser(flow.if_out_index, ParserType::Interface)) {
        return true;
    }
    if (_f_enabled[Filters::GeoLocNotFound] && geo::GeoIP().enabled()) {
        if (!flow.is_ipv6) {
            struct sockaddr_in sa4;
            if ((IPv4_to_sockaddr(flow.ipv4_in, &sa4) && geo::GeoIP().getGeoLocString(&sa4) != "Unknown")
                && (IPv4_to_sockaddr(flow.ipv4_out, &sa4) && geo::GeoIP().getGeoLocString(&sa4) != "Unknown")) {
                return true;
            }
        } else {
            struct sockaddr_in6 sa6;
            if ((IPv6_to_sockaddr(flow.ipv6_in, &sa6) && geo::GeoIP().getGeoLocString(&sa6) != "Unknown")
                && (IPv6_to_sockaddr(flow.ipv6_out, &sa6) && geo::GeoIP().getGeoLocString(&sa6) != "Unknown")) {
                return true;
            }
        }
    }
    if (_f_enabled[Filters::AsnNotFound] && geo::GeoASN().enabled()) {
        if (!flow.is_ipv6) {
            struct sockaddr_in sa4;
            if ((IPv4_to_sockaddr(flow.ipv4_in, &sa4) && geo::GeoASN().getASNString(&sa4) != "Unknown")
                && (IPv4_to_sockaddr(flow.ipv4_out, &sa4) && geo::GeoASN().getASNString(&sa4) != "Unknown")) {
                return true;
            }
        } else {
            struct sockaddr_in6 sa6;
            if ((IPv6_to_sockaddr(flow.ipv6_in, &sa6) && geo::GeoASN().getASNString(&sa6) != "Unknown")
                && (IPv6_to_sockaddr(flow.ipv6_out, &sa6) && geo::GeoASN().getASNString(&sa6) != "Unknown")) {
                return true;
            }
        }
    }
    return false;
}

void FlowStreamHandler::_parse_ports_or_interfaces(const std::vector<std::string> &port_interface_list, ParserType type)
{
    for (const auto &port_or_interface : port_interface_list) {
        try {
            auto delimiter = port_or_interface.find('-');
            if (delimiter != port_or_interface.npos) {
                auto first_value = std::stoul(port_or_interface.substr(0, delimiter));
                auto last_value = std::stoul(port_or_interface.substr(delimiter + 1));
                if (first_value > last_value) {
                    _parsed_list[type].push_back(std::make_pair(last_value, first_value));
                } else {
                    _parsed_list[type].push_back(std::make_pair(first_value, last_value));
                }
            } else {
                if (!std::all_of(port_or_interface.begin(), port_or_interface.end(), ::isdigit)) {
                    throw StreamHandlerException("is not a digit");
                };
                auto value = std::stoul(port_or_interface);
                _parsed_list[type].push_back(std::make_pair(value, value));
            }
        } catch ([[maybe_unused]] const std::exception &e) {
            throw StreamHandlerException(fmt::format("FlowHandler: invalid '{}' filter value: {}", _parser_types_string.at(type), port_or_interface));
        }
    }
}

inline bool FlowStreamHandler::_match_parser(uint32_t value, ParserType type)
{
    return std::any_of(_parsed_list[type].begin(), _parsed_list[type].end(), [value](auto pair) {
        return (value >= pair.first && value <= pair.second);
    });
}

void FlowStreamHandler::_parse_host_specs(const std::vector<std::string> &host_list, bool device)
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
            (device) ? _IPv6_devices_list.emplace_back(ipv6, cidr_number) : _IPv6_ips_list.emplace_back(ipv6, cidr_number);
        } else {
            if (cidr_number < 0 || cidr_number > 32) {
                throw StreamHandlerException(fmt::format("invalid CIDR: {}", host));
            }
            in_addr ipv4;
            if (inet_pton(AF_INET, ip.c_str(), &ipv4) != 1) {
                throw StreamHandlerException(fmt::format("invalid IPv4 address: {}", ip));
            }
            (device) ? _IPv4_devices_list.emplace_back(ipv4, cidr_number) : _IPv4_ips_list.emplace_back(ipv4, cidr_number);
        }
    }
}

inline bool FlowStreamHandler::_match_subnet(std::vector<Ipv4Subnet> &IPv4_subnet_list, std::vector<Ipv6Subnet> &IPv6_subnet_list, uint32_t ipv4_val, const uint8_t *ipv6_val)
{
    if (ipv4_val && IPv4_subnet_list.size() > 0) {
        in_addr ipv4;
        std::memcpy(&ipv4, &ipv4_val, sizeof(in_addr));
        for (const auto &net : IPv4_subnet_list) {
            uint8_t cidr = net.second;
            if (cidr == 0) {
                return true;
            }
            uint32_t mask = htonl((0xFFFFFFFFu) << (32 - cidr));
            if (!((ipv4.s_addr ^ net.first.s_addr) & mask)) {
                return true;
            }
        }
    } else if (ipv6_val && IPv6_subnet_list.size() > 0) {
        in6_addr ipv6;
        std::memcpy(&ipv6, ipv6_val, sizeof(in6_addr));
        for (const auto &net : IPv6_subnet_list) {
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
        _counters.filtered += other._counters.filtered;
        _counters.total += other._counters.total;
    }

    _volume.merge(other._volume);

    for (const auto &device : other._devices_metrics) {
        const auto &deviceId = device.first;
        const auto &device_data = device.second;

        _devices_metrics[deviceId]->payload_size.merge(device.second->payload_size);

        if (group_enabled(group::FlowMetrics::Counters)) {
            _devices_metrics[deviceId]->counters.UDP += device.second->counters.UDP;
            _devices_metrics[deviceId]->counters.TCP += device.second->counters.TCP;
            _devices_metrics[deviceId]->counters.OtherL4 += device.second->counters.OtherL4;
            _devices_metrics[deviceId]->counters.IPv4 += device.second->counters.IPv4;
            _devices_metrics[deviceId]->counters.IPv6 += device.second->counters.IPv6;
            _devices_metrics[deviceId]->counters.filtered += device.second->counters.filtered;
            _devices_metrics[deviceId]->counters.total += device.second->counters.total;
        }

        if (group_enabled(group::FlowMetrics::TopGeo)) {
            _devices_metrics[deviceId]->topGeoLoc.merge(device.second->topGeoLoc);
            _devices_metrics[deviceId]->topASN.merge(device.second->topASN);
        }

        if (group_enabled(group::FlowMetrics::Cardinality)) {
            _devices_metrics[deviceId]->conversationsCard.merge(device.second->conversationsCard);
            _devices_metrics[deviceId]->srcIPCard.merge(device.second->srcIPCard);
            _devices_metrics[deviceId]->dstIPCard.merge(device.second->dstIPCard);
            _devices_metrics[deviceId]->srcPortCard.merge(device.second->srcPortCard);
            _devices_metrics[deviceId]->dstPortCard.merge(device.second->dstPortCard);
        }

        if (group_enabled(group::FlowMetrics::TopByBytes)) {
            _devices_metrics[deviceId]->topByBytes.topSrcIP.merge(device.second->topByBytes.topSrcIP);
            _devices_metrics[deviceId]->topByBytes.topDstIP.merge(device.second->topByBytes.topDstIP);
            _devices_metrics[deviceId]->topByBytes.topSrcPort.merge(device.second->topByBytes.topSrcPort);
            _devices_metrics[deviceId]->topByBytes.topDstPort.merge(device.second->topByBytes.topDstPort);
            _devices_metrics[deviceId]->topByBytes.topSrcIPandPort.merge(device.second->topByBytes.topSrcIPandPort);
            _devices_metrics[deviceId]->topByBytes.topDstIPandPort.merge(device.second->topByBytes.topDstIPandPort);
            _devices_metrics[deviceId]->topByBytes.topConversations.merge(device.second->topByBytes.topConversations);
            _devices_metrics[deviceId]->topByBytes.topInIfIndex.merge(device.second->topByBytes.topInIfIndex);
            _devices_metrics[deviceId]->topByBytes.topOutIfIndex.merge(device.second->topByBytes.topOutIfIndex);
        }

        if (group_enabled(group::FlowMetrics::TopByPackets)) {
            _devices_metrics[deviceId]->topByPackets.topSrcIP.merge(device.second->topByPackets.topSrcIP);
            _devices_metrics[deviceId]->topByPackets.topDstIP.merge(device.second->topByPackets.topDstIP);
            _devices_metrics[deviceId]->topByPackets.topSrcPort.merge(device.second->topByPackets.topSrcPort);
            _devices_metrics[deviceId]->topByPackets.topDstPort.merge(device.second->topByPackets.topDstPort);
            _devices_metrics[deviceId]->topByPackets.topSrcIPandPort.merge(device.second->topByPackets.topSrcIPandPort);
            _devices_metrics[deviceId]->topByPackets.topDstIPandPort.merge(device.second->topByPackets.topDstIPandPort);
            _devices_metrics[deviceId]->topByPackets.topConversations.merge(device.second->topByPackets.topConversations);
            _devices_metrics[deviceId]->topByPackets.topInIfIndex.merge(device.second->topByPackets.topInIfIndex);
            _devices_metrics[deviceId]->topByPackets.topOutIfIndex.merge(device.second->topByPackets.topOutIfIndex);
        }
    }
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
        _counters.filtered.to_prometheus(out, add_labels);
        _counters.total.to_prometheus(out, add_labels);
    }

    _volume.to_prometheus(out, add_labels);

    for (const auto &device : _devices_metrics) {
        auto device_labels = add_labels;
        device_labels["device"] = device.first;

        device.second->payload_size.to_prometheus(out, device_labels);

        if (group_enabled(group::FlowMetrics::Counters)) {
            device.second->counters.UDP.to_prometheus(out, device_labels);
            device.second->counters.TCP.to_prometheus(out, device_labels);
            device.second->counters.OtherL4.to_prometheus(out, device_labels);
            device.second->counters.IPv4.to_prometheus(out, device_labels);
            device.second->counters.IPv6.to_prometheus(out, device_labels);
            device.second->counters.filtered.to_prometheus(out, device_labels);
            device.second->counters.total.to_prometheus(out, device_labels);
        }

        if (group_enabled(group::FlowMetrics::TopGeo)) {
            device.second->topGeoLoc.to_prometheus(out, device_labels);
            device.second->topASN.to_prometheus(out, device_labels);
        }

        if (group_enabled(group::FlowMetrics::Cardinality)) {
            device.second->conversationsCard.to_prometheus(out, device_labels);
            device.second->srcIPCard.to_prometheus(out, device_labels);
            device.second->dstIPCard.to_prometheus(out, device_labels);
            device.second->srcPortCard.to_prometheus(out, device_labels);
            device.second->dstPortCard.to_prometheus(out, device_labels);
        }

        if (group_enabled(group::FlowMetrics::TopByBytes)) {
            device.second->topByBytes.topSrcIP.to_prometheus(out, device_labels);
            device.second->topByBytes.topDstIP.to_prometheus(out, device_labels);
            device.second->topByBytes.topSrcPort.to_prometheus(out, device_labels, [](const uint16_t &val) { return std::to_string(val); });
            device.second->topByBytes.topDstPort.to_prometheus(out, device_labels, [](const uint16_t &val) { return std::to_string(val); });
            device.second->topByBytes.topSrcIPandPort.to_prometheus(out, device_labels);
            device.second->topByBytes.topDstIPandPort.to_prometheus(out, device_labels);
            device.second->topByBytes.topConversations.to_prometheus(out, device_labels);
            device.second->topByBytes.topInIfIndex.to_prometheus(out, device_labels, [](const uint32_t &val) { return std::to_string(val); });
            device.second->topByBytes.topOutIfIndex.to_prometheus(out, device_labels, [](const uint32_t &val) { return std::to_string(val); });
        }

        if (group_enabled(group::FlowMetrics::TopByPackets)) {
            device.second->topByPackets.topSrcIP.to_prometheus(out, device_labels);
            device.second->topByPackets.topDstIP.to_prometheus(out, device_labels);
            device.second->topByPackets.topSrcPort.to_prometheus(out, device_labels, [](const uint16_t &val) { return std::to_string(val); });
            device.second->topByPackets.topDstPort.to_prometheus(out, device_labels, [](const uint16_t &val) { return std::to_string(val); });
            device.second->topByPackets.topSrcIPandPort.to_prometheus(out, device_labels);
            device.second->topByPackets.topDstIPandPort.to_prometheus(out, device_labels);
            device.second->topByPackets.topConversations.to_prometheus(out, device_labels);
            device.second->topByPackets.topInIfIndex.to_prometheus(out, device_labels, [](const uint32_t &val) { return std::to_string(val); });
            device.second->topByPackets.topOutIfIndex.to_prometheus(out, device_labels, [](const uint32_t &val) { return std::to_string(val); });
        }
    }
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
        _counters.filtered.to_json(j);
        _counters.total.to_json(j);
    }

    _volume.to_json(j);

    for (const auto &device : _devices_metrics) {
        auto deviceId = device.first;
        device.second->payload_size.to_json(j["devices"][deviceId]);

        if (group_enabled(group::FlowMetrics::Counters)) {
            device.second->counters.UDP.to_json(j["devices"][deviceId]);
            device.second->counters.TCP.to_json(j["devices"][deviceId]);
            device.second->counters.OtherL4.to_json(j["devices"][deviceId]);
            device.second->counters.IPv4.to_json(j["devices"][deviceId]);
            device.second->counters.IPv6.to_json(j["devices"][deviceId]);
            device.second->counters.filtered.to_json(j["devices"][deviceId]);
            device.second->counters.total.to_json(j["devices"][deviceId]);
        }

        if (group_enabled(group::FlowMetrics::TopGeo)) {
            device.second->topGeoLoc.to_json(j["devices"][deviceId]);
            device.second->topASN.to_json(j["devices"][deviceId]);
        }

        if (group_enabled(group::FlowMetrics::Cardinality)) {
            device.second->conversationsCard.to_json(j["devices"][deviceId]);
            device.second->srcIPCard.to_json(j["devices"][deviceId]);
            device.second->dstIPCard.to_json(j["devices"][deviceId]);
            device.second->srcPortCard.to_json(j["devices"][deviceId]);
            device.second->dstPortCard.to_json(j["devices"][deviceId]);
        }

        if (group_enabled(group::FlowMetrics::TopByBytes)) {
            device.second->topByBytes.topSrcIP.to_json(j["devices"][deviceId]);
            device.second->topByBytes.topDstIP.to_json(j["devices"][deviceId]);
            device.second->topByBytes.topSrcPort.to_json(j["devices"][deviceId], [](const uint16_t &val) { return std::to_string(val); });
            device.second->topByBytes.topDstPort.to_json(j["devices"][deviceId], [](const uint16_t &val) { return std::to_string(val); });
            device.second->topByBytes.topSrcIPandPort.to_json(j["devices"][deviceId]);
            device.second->topByBytes.topDstIPandPort.to_json(j["devices"][deviceId]);
            device.second->topByBytes.topConversations.to_json(j["devices"][deviceId]);
            device.second->topByBytes.topInIfIndex.to_json(j["devices"][deviceId], [](const uint32_t &val) { return std::to_string(val); });
            device.second->topByBytes.topOutIfIndex.to_json(j["devices"][deviceId], [](const uint32_t &val) { return std::to_string(val); });
        }

        if (group_enabled(group::FlowMetrics::TopByPackets)) {
            device.second->topByPackets.topSrcIP.to_json(j["devices"][deviceId]);
            device.second->topByPackets.topDstIP.to_json(j["devices"][deviceId]);
            device.second->topByPackets.topSrcPort.to_json(j["devices"][deviceId], [](const uint16_t &val) { return std::to_string(val); });
            device.second->topByPackets.topDstPort.to_json(j["devices"][deviceId], [](const uint16_t &val) { return std::to_string(val); });
            device.second->topByPackets.topSrcIPandPort.to_json(j["devices"][deviceId]);
            device.second->topByPackets.topDstIPandPort.to_json(j["devices"][deviceId]);
            device.second->topByPackets.topConversations.to_json(j["devices"][deviceId]);
            device.second->topByPackets.topInIfIndex.to_json(j["devices"][deviceId], [](const uint32_t &val) { return std::to_string(val); });
            device.second->topByPackets.topOutIfIndex.to_json(j["devices"][deviceId], [](const uint32_t &val) { return std::to_string(val); });
        }
    }
}

void FlowMetricsBucket::process_flow(bool deep, const FlowPacket &payload)
{
    std::unique_lock lock(_mutex);

    if (!_devices_metrics.count(payload.device_id)) {
        _devices_metrics[payload.device_id] = std::make_unique<FlowDevice>();
        _devices_metrics[payload.device_id]->set_topn_count(_topn_count);
    }

    auto device_flow = _devices_metrics[payload.device_id].get();

    if (group_enabled(group::FlowMetrics::Counters)) {
        _counters.filtered += payload.filtered;
        device_flow->counters.filtered += payload.filtered;
    }

    _volume.update(payload.raw_size);

    for (const auto &flow : payload.flow_data) {
        _rate += flow.packets;
        _throughput += flow.payload_size;

        if (group_enabled(group::FlowMetrics::Counters)) {
            ++_counters.total;
            ++device_flow->counters.total;

            if (flow.is_ipv6) {
                ++device_flow->counters.IPv6;
            } else {
                ++device_flow->counters.IPv4;
            }

            switch (flow.l4) {
            case IP_PROTOCOL::UDP:
                ++device_flow->counters.UDP;
                break;
            case IP_PROTOCOL::TCP:
                ++device_flow->counters.TCP;
                break;
            default:
                ++device_flow->counters.OtherL4;
                break;
            }
        }

        device_flow->payload_size.update(flow.payload_size);

        if (!deep) {
            continue;
        }

        if (group_enabled(group::FlowMetrics::TopByBytes)) {
            (flow.src_port > 0) ? device_flow->topByBytes.topSrcPort.update(flow.src_port, flow.payload_size) : void();
            (flow.dst_port > 0) ? device_flow->topByBytes.topDstPort.update(flow.dst_port, flow.payload_size) : void();
            device_flow->topByBytes.topInIfIndex.update(flow.if_in_index, flow.payload_size);
            device_flow->topByBytes.topOutIfIndex.update(flow.if_out_index, flow.payload_size);
        }

        if (group_enabled(group::FlowMetrics::TopByPackets)) {
            (flow.src_port > 0) ? device_flow->topByPackets.topSrcPort.update(flow.src_port, flow.packets) : void();
            (flow.dst_port > 0) ? device_flow->topByPackets.topDstPort.update(flow.dst_port, flow.packets) : void();
            device_flow->topByPackets.topInIfIndex.update(flow.if_in_index, flow.packets);
            device_flow->topByPackets.topOutIfIndex.update(flow.if_out_index, flow.packets);
        }

        if (group_enabled(group::FlowMetrics::Cardinality)) {
            (flow.src_port > 0) ? device_flow->srcPortCard.update(flow.src_port) : void();
            (flow.dst_port > 0) ? device_flow->dstPortCard.update(flow.dst_port) : void();
        }

        std::string application_src;
        std::string application_dst;

        if (!flow.is_ipv6 && flow.ipv4_in.isValid()) {
            group_enabled(group::FlowMetrics::Cardinality) ? device_flow->srcIPCard.update(flow.ipv4_in.toInt()) : void();
            auto ip = flow.ipv4_in.toString();
            application_src = ip + ":" + std::to_string(flow.src_port);
            if (group_enabled(group::FlowMetrics::TopByBytes)) {
                device_flow->topByBytes.topSrcIP.update(ip, flow.payload_size);
                (flow.src_port > 0) ? device_flow->topByBytes.topSrcIPandPort.update(application_src, flow.payload_size) : void();
            }
            if (group_enabled(group::FlowMetrics::TopByPackets)) {
                device_flow->topByPackets.topSrcIP.update(ip, flow.packets);
                (flow.src_port > 0) ? device_flow->topByPackets.topSrcIPandPort.update(application_src, flow.packets) : void();
            }
            _process_geo_metrics(device_flow, flow.ipv4_in);
        } else if (flow.is_ipv6 && flow.ipv6_in.isValid()) {
            group_enabled(group::FlowMetrics::Cardinality) ? device_flow->srcIPCard.update(reinterpret_cast<const void *>(flow.ipv6_in.toBytes()), 16) : void();
            auto ip = flow.ipv6_in.toString();
            application_src = ip + ":" + std::to_string(flow.src_port);
            if (group_enabled(group::FlowMetrics::TopByPackets)) {
                device_flow->topByBytes.topSrcIP.update(ip, flow.payload_size);
                (flow.src_port > 0) ? device_flow->topByBytes.topSrcIPandPort.update(application_src, flow.payload_size) : void();
            }
            if (group_enabled(group::FlowMetrics::TopByPackets)) {
                device_flow->topByPackets.topSrcIP.update(ip, flow.packets);
                (flow.src_port > 0) ? device_flow->topByPackets.topSrcIPandPort.update(application_src, flow.packets) : void();
            }
            _process_geo_metrics(device_flow, flow.ipv6_in);
        }

        if (!flow.is_ipv6 && flow.ipv4_out.isValid()) {
            group_enabled(group::FlowMetrics::Cardinality) ? device_flow->dstIPCard.update(flow.ipv4_out.toInt()) : void();
            auto ip = flow.ipv4_out.toString();
            application_dst = ip + ":" + std::to_string(flow.dst_port);
            if (group_enabled(group::FlowMetrics::TopByBytes)) {
                device_flow->topByBytes.topDstIP.update(ip, flow.payload_size);
                (flow.dst_port > 0) ? device_flow->topByBytes.topDstIPandPort.update(application_dst, flow.payload_size) : void();
            }
            if (group_enabled(group::FlowMetrics::TopByPackets)) {
                device_flow->topByPackets.topDstIP.update(ip, flow.packets);
                (flow.dst_port > 0) ? device_flow->topByPackets.topDstIPandPort.update(application_dst, flow.packets) : void();
            }
            _process_geo_metrics(device_flow, flow.ipv4_out);
        } else if (flow.is_ipv6 && flow.ipv6_out.isValid()) {
            group_enabled(group::FlowMetrics::Cardinality) ? device_flow->dstIPCard.update(reinterpret_cast<const void *>(flow.ipv6_out.toBytes()), 16) : void();
            auto ip = flow.ipv6_in.toString();
            application_dst = ip + ":" + std::to_string(flow.dst_port);
            if (group_enabled(group::FlowMetrics::TopByBytes)) {
                device_flow->topByBytes.topDstIP.update(ip, flow.payload_size);
                (flow.dst_port > 0) ? device_flow->topByBytes.topDstIPandPort.update(application_dst, flow.payload_size) : void();
            }
            if (group_enabled(group::FlowMetrics::TopByPackets)) {
                device_flow->topByPackets.topDstIP.update(ip, flow.packets);
                (flow.dst_port > 0) ? device_flow->topByPackets.topDstIPandPort.update(application_dst, flow.packets) : void();
            }
            _process_geo_metrics(device_flow, flow.ipv6_out);
        }

        if (flow.src_port > 0 && flow.dst_port > 0 && !application_src.empty() && !application_dst.empty()) {
            std::string conversation;
            if (application_src > application_dst) {
                conversation = application_dst + "/" + application_src;
            } else {
                conversation = application_src + "/" + application_dst;
            }
            device_flow->conversationsCard.update(conversation);
            group_enabled(group::FlowMetrics::TopByBytes) ? device_flow->topByBytes.topConversations.update(conversation, flow.payload_size) : void();
            group_enabled(group::FlowMetrics::TopByPackets) ? device_flow->topByPackets.topConversations.update(conversation, flow.packets) : void();
        }
    }
}

inline void FlowMetricsBucket::_process_geo_metrics(FlowDevice *device, const pcpp::IPv4Address &ipv4)
{
    if (geo::enabled() && group_enabled(group::FlowMetrics::TopGeo)) {
        struct sockaddr_in sa4;
        if (IPv4_to_sockaddr(ipv4, &sa4)) {
            if (geo::GeoIP().enabled()) {
                device->topGeoLoc.update(geo::GeoIP().getGeoLocString(&sa4));
            }
            if (geo::GeoASN().enabled()) {
                device->topASN.update(geo::GeoASN().getASNString(&sa4));
            }
        }
    }
}

inline void FlowMetricsBucket::_process_geo_metrics(FlowDevice *device, const pcpp::IPv6Address &ipv6)
{
    if (geo::enabled() && group_enabled(group::FlowMetrics::TopGeo)) {
        struct sockaddr_in6 sa6;
        if (IPv6_to_sockaddr(ipv6, &sa6)) {
            if (geo::GeoIP().enabled()) {
                device->topGeoLoc.update(geo::GeoIP().getGeoLocString(&sa6));
            }
            if (geo::GeoASN().enabled()) {
                device->topASN.update(geo::GeoASN().getASNString(&sa6));
            }
        }
    }
}

void FlowMetricsManager::process_flow(const FlowPacket &payload)
{
    new_event(payload.stamp);
    // process in the "live" bucket
    live_bucket()->process_flow(_deep_sampling_now, payload);
}
}
