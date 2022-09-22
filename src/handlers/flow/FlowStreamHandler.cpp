/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "FlowStreamHandler.h"
#include "GeoDB.h"
#include "HandlerModulePlugin.h"
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

template <typename Out>
static void split(const std::string &s, char delim, Out result)
{
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}

static std::vector<std::string> split(const std::string &s, char delim)
{
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

FlowStreamHandler::FlowStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config)
    : visor::StreamMetricsHandler<FlowMetricsManager>(name, window_config)
    , _sample_rate_scaling(true)
{
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

    // Setup Configs
    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    EnrichMap enrich_data;
    if (config_exists("device_map")) {
        for (const auto &device_info : config_get<StringList>("device_map")) {
            std::vector<std::string> data = split(device_info, ',');
            if (data.size() < 2) {
                // should at least contain device name and ip
                continue;
            }
            DeviceEnrich *device{nullptr};
            if (auto it = enrich_data.find(data[1]); it != enrich_data.end()) {
                device = &it->second;
            } else {
                enrich_data[data[1]] = DeviceEnrich{data[0], {}};
                device = &enrich_data[data[1]];
            }
            if (data.size() < 4) {
                // should have interface information
                continue;
            }
            auto if_index = static_cast<uint32_t>(std::stol(data[3]));
            if (auto it = device->interfaces.find(if_index); it == device->interfaces.end()) {
                if (data.size() > 4) {
                    device->interfaces[if_index] = InterfaceEnrich{data[2], data[4]};
                } else {
                    device->interfaces[if_index] = InterfaceEnrich{data[2], std::string()};
                }
            }
        }
    }

    std::unordered_map<std::string, std::string> concat_if;
    if (config_exists("first_filter_if_as_label") && config_get<bool>("first_filter_if_as_label") && config_exists("only_interfaces")) {
        concat_if["default"] = config_get<StringList>("only_interfaces")[0];
        auto interface = static_cast<uint32_t>(std::stoul(config_get<StringList>("only_interfaces")[0]));
        for (const auto &data : enrich_data) {
            auto it = data.second.interfaces.find(interface);
            if (it != data.second.interfaces.end()) {
                concat_if[data.first] = it->second.name;
            }
        }
    }
    _metrics->set_enrich_data(std::move(concat_if), std::move(enrich_data));

    // Setup Filters
    if (config_exists("only_ips")) {
        _parse_host_specs(config_get<StringList>("only_ips"));
        _f_enabled.set(Filters::OnlyIps);
    }

    if (config_exists("only_devices")) {
        _parse_devices_ips(config_get<StringList>("only_devices"));
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

void FlowStreamHandler::process_sflow_cb(const SFSample &payload, [[maybe_unused]] size_t rawSize)
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

    FlowPacket packet(agentId, stamp);

    if (_f_enabled[Filters::OnlyDevices]) {
        if (auto ipv4 = pcpp::IPv4Address(packet.device_id); ipv4.isValid() && std::none_of(_IPv4_devices_list.begin(), _IPv4_devices_list.end(), [ipv4](const auto &item) {
                return ipv4 == item;
            })) {
            _metrics->process_filtered(stamp, payload.elements.size());
            return;
        } else if (auto ipv6 = pcpp::IPv6Address(packet.device_id); ipv6.isValid() && std::none_of(_IPv6_devices_list.begin(), _IPv6_devices_list.end(), [ipv6](const auto &item) {
                       return ipv6 == item;
                   })) {
            _metrics->process_filtered(stamp, payload.elements.size());
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

void FlowStreamHandler::process_netflow_cb(const std::string &senderIP, const NFSample &payload, [[maybe_unused]] size_t rawSize)
{
    timespec stamp;
    if (payload.time_sec || payload.time_nanosec) {
        stamp.tv_sec = payload.time_sec;
        stamp.tv_nsec = payload.time_nanosec;
    } else {
        // use now()
        std::timespec_get(&stamp, TIME_UTC);
    }
    FlowPacket packet(senderIP, stamp);

    if (_f_enabled[Filters::OnlyDevices]) {
        if (auto ipv4 = pcpp::IPv4Address(packet.device_id); ipv4.isValid() && std::none_of(_IPv4_devices_list.begin(), _IPv4_devices_list.end(), [ipv4](const auto &item) {
                return ipv4 == item;
            })) {
            _metrics->process_filtered(stamp, payload.flows.size());
            return;
        } else if (auto ipv6 = pcpp::IPv6Address(packet.device_id); ipv6.isValid() && std::none_of(_IPv6_devices_list.begin(), _IPv6_devices_list.end(), [ipv6](const auto &item) {
                       return ipv6 == item;
                   })) {
            _metrics->process_filtered(stamp, payload.flows.size());
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
        if (flow.is_ipv6 && !_match_subnet(0, flow.ipv6_in.toBytes()) && !_match_subnet(0, flow.ipv6_out.toBytes())) {
            return true;
        } else if (!_match_subnet(flow.ipv4_in.toInt()) && !_match_subnet(flow.ipv4_out.toInt())) {
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
    if (_f_enabled[Filters::GeoLocNotFound] && HandlerModulePlugin::city->enabled()) {
        if (!flow.is_ipv6) {
            struct sockaddr_in sa4;
            if ((IPv4_to_sockaddr(flow.ipv4_in, &sa4) && HandlerModulePlugin::city->getGeoLocString(&sa4) != "Unknown")
                && (IPv4_to_sockaddr(flow.ipv4_out, &sa4) && HandlerModulePlugin::city->getGeoLocString(&sa4) != "Unknown")) {
                return true;
            }
        } else {
            struct sockaddr_in6 sa6;
            if ((IPv6_to_sockaddr(flow.ipv6_in, &sa6) && HandlerModulePlugin::city->getGeoLocString(&sa6) != "Unknown")
                && (IPv6_to_sockaddr(flow.ipv6_out, &sa6) && HandlerModulePlugin::city->getGeoLocString(&sa6) != "Unknown")) {
                return true;
            }
        }
    }
    if (_f_enabled[Filters::AsnNotFound] && HandlerModulePlugin::asn->enabled()) {
        if (!flow.is_ipv6) {
            struct sockaddr_in sa4;
            if ((IPv4_to_sockaddr(flow.ipv4_in, &sa4) && HandlerModulePlugin::asn->getASNString(&sa4) != "Unknown")
                && (IPv4_to_sockaddr(flow.ipv4_out, &sa4) && HandlerModulePlugin::asn->getASNString(&sa4) != "Unknown")) {
                return true;
            }
        } else {
            struct sockaddr_in6 sa6;
            if ((IPv6_to_sockaddr(flow.ipv6_in, &sa6) && HandlerModulePlugin::asn->getASNString(&sa6) != "Unknown")
                && (IPv6_to_sockaddr(flow.ipv6_out, &sa6) && HandlerModulePlugin::asn->getASNString(&sa6) != "Unknown")) {
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

void FlowStreamHandler::_parse_devices_ips(const std::vector<std::string> &device_list)
{
    for (const auto &device : device_list) {
        if (auto ipv4 = pcpp::IPv4Address(device); ipv4.isValid()) {
            _IPv4_devices_list.push_back(ipv4);
        } else if (auto ipv6 = pcpp::IPv6Address(device); ipv6.isValid()) {
            _IPv6_devices_list.push_back(ipv6);
        } else {
            throw StreamHandlerException(fmt::format("invalid device IP: {}", device));
        }
    }
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
            _IPv6_ips_list.emplace_back(ipv6, cidr_number);
        } else {
            if (cidr_number < 0 || cidr_number > 32) {
                throw StreamHandlerException(fmt::format("invalid CIDR: {}", host));
            }
            in_addr ipv4;
            if (inet_pton(AF_INET, ip.c_str(), &ipv4) != 1) {
                throw StreamHandlerException(fmt::format("invalid IPv4 address: {}", ip));
            }
            _IPv4_ips_list.emplace_back(ipv4, cidr_number);
        }
    }
}

inline bool FlowStreamHandler::_match_subnet(uint32_t ipv4_val, const uint8_t *ipv6_val)
{
    if (ipv4_val && _IPv4_ips_list.size() > 0) {
        in_addr ipv4;
        std::memcpy(&ipv4, &ipv4_val, sizeof(in_addr));
        for (const auto &net : _IPv4_ips_list) {
            uint8_t cidr = net.second;
            if (cidr == 0) {
                return true;
            }
            uint32_t mask = htonl((0xFFFFFFFFu) << (32 - cidr));
            if (!((ipv4.s_addr ^ net.first.s_addr) & mask)) {
                return true;
            }
        }
    } else if (ipv6_val && _IPv6_ips_list.size() > 0) {
        in6_addr ipv6;
        std::memcpy(&ipv6, ipv6_val, sizeof(in6_addr));
        for (const auto &net : _IPv6_ips_list) {
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

void FlowMetricsBucket::specialized_merge(const AbstractMetricsBucket &o, Metric::Aggregate agg_operator)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const FlowMetricsBucket &>(o);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    if (group_enabled(group::FlowMetrics::Counters)) {
        _counters.filtered += other._counters.filtered;
        _counters.total += other._counters.total;
    }

    for (const auto &device : other._devices_metrics) {
        const auto &deviceId = device.first;

        if (group_enabled(group::FlowMetrics::Counters)) {
            _devices_metrics[deviceId]->counters.UDP += device.second->counters.UDP;
            _devices_metrics[deviceId]->counters.TCP += device.second->counters.TCP;
            _devices_metrics[deviceId]->counters.OtherL4 += device.second->counters.OtherL4;
            _devices_metrics[deviceId]->counters.IPv4 += device.second->counters.IPv4;
            _devices_metrics[deviceId]->counters.IPv6 += device.second->counters.IPv6;
            _devices_metrics[deviceId]->counters.filtered += device.second->counters.filtered;
            _devices_metrics[deviceId]->counters.total += device.second->counters.total;
        }

        if (group_enabled(group::FlowMetrics::Cardinality)) {
            if (group_enabled(group::FlowMetrics::Conversations)) {
                _devices_metrics[deviceId]->conversationsCard.merge(device.second->conversationsCard);
            }
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
            if (group_enabled(group::FlowMetrics::Conversations)) {
                _devices_metrics[deviceId]->topByBytes.topConversations.merge(device.second->topByBytes.topConversations);
            }
            _devices_metrics[deviceId]->topByBytes.topInIfIndex.merge(device.second->topByBytes.topInIfIndex);
            _devices_metrics[deviceId]->topByBytes.topOutIfIndex.merge(device.second->topByBytes.topOutIfIndex);
            if (group_enabled(group::FlowMetrics::TopGeo)) {
                _devices_metrics[deviceId]->topByBytes.topGeoLoc.merge(device.second->topByBytes.topGeoLoc);
                _devices_metrics[deviceId]->topByBytes.topASN.merge(device.second->topByBytes.topASN);
            }
        }

        if (group_enabled(group::FlowMetrics::TopByPackets)) {
            _devices_metrics[deviceId]->topByPackets.topSrcIP.merge(device.second->topByPackets.topSrcIP);
            _devices_metrics[deviceId]->topByPackets.topDstIP.merge(device.second->topByPackets.topDstIP);
            _devices_metrics[deviceId]->topByPackets.topSrcPort.merge(device.second->topByPackets.topSrcPort);
            _devices_metrics[deviceId]->topByPackets.topDstPort.merge(device.second->topByPackets.topDstPort);
            _devices_metrics[deviceId]->topByPackets.topSrcIPandPort.merge(device.second->topByPackets.topSrcIPandPort);
            _devices_metrics[deviceId]->topByPackets.topDstIPandPort.merge(device.second->topByPackets.topDstIPandPort);
            if (group_enabled(group::FlowMetrics::Conversations)) {
                _devices_metrics[deviceId]->topByPackets.topConversations.merge(device.second->topByPackets.topConversations);
            }
            _devices_metrics[deviceId]->topByPackets.topInIfIndex.merge(device.second->topByPackets.topInIfIndex);
            _devices_metrics[deviceId]->topByPackets.topOutIfIndex.merge(device.second->topByPackets.topOutIfIndex);
            if (group_enabled(group::FlowMetrics::TopGeo)) {
                _devices_metrics[deviceId]->topByPackets.topGeoLoc.merge(device.second->topByPackets.topGeoLoc);
                _devices_metrics[deviceId]->topByPackets.topASN.merge(device.second->topByPackets.topASN);
            }
        }
    }
}

void FlowMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{
    std::shared_lock r_lock(_mutex);

    if (group_enabled(group::FlowMetrics::Counters)) {
        _counters.filtered.to_prometheus(out, add_labels);
        _counters.total.to_prometheus(out, add_labels);
    }

    for (const auto &device : _devices_metrics) {
        auto device_labels = add_labels;
        auto deviceId = device.first;
        DeviceEnrich *dev{nullptr};
        if (_enrich_data) {
            if (auto it = _enrich_data->find(deviceId); it != _enrich_data->end()) {
                dev = &it->second;
                deviceId = it->second.name;
            }
        }
        device_labels["device"] = deviceId;
        if (_concat_if) {
            if (auto it = _concat_if->find(device.first); (it != _concat_if->end()) && !it->second.empty()) {
                device_labels["device_interface"] = deviceId + "|" + it->second;
            } else {
                device_labels["device_interface"] = deviceId + "|" + _concat_if->at("default");
            }
        }

        if (group_enabled(group::FlowMetrics::Counters)) {
            device.second->counters.UDP.to_prometheus(out, device_labels);
            device.second->counters.TCP.to_prometheus(out, device_labels);
            device.second->counters.OtherL4.to_prometheus(out, device_labels);
            device.second->counters.IPv4.to_prometheus(out, device_labels);
            device.second->counters.IPv6.to_prometheus(out, device_labels);
            device.second->counters.filtered.to_prometheus(out, device_labels);
            device.second->counters.total.to_prometheus(out, device_labels);
        }

        if (group_enabled(group::FlowMetrics::Cardinality)) {
            if (group_enabled(group::FlowMetrics::Conversations)) {
                device.second->conversationsCard.to_prometheus(out, device_labels);
            }
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
            if (group_enabled(group::FlowMetrics::Conversations)) {
                device.second->topByBytes.topConversations.to_prometheus(out, device_labels);
            }
            device.second->topByBytes.topInIfIndex.to_prometheus(out, device_labels, [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
            device.second->topByBytes.topOutIfIndex.to_prometheus(out, device_labels, [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
            if (group_enabled(group::FlowMetrics::TopGeo)) {
                device.second->topByBytes.topGeoLoc.to_prometheus(out, device_labels);
                device.second->topByBytes.topASN.to_prometheus(out, device_labels);
            }
        }

        if (group_enabled(group::FlowMetrics::TopByPackets)) {
            device.second->topByPackets.topSrcIP.to_prometheus(out, device_labels);
            device.second->topByPackets.topDstIP.to_prometheus(out, device_labels);
            device.second->topByPackets.topSrcPort.to_prometheus(out, device_labels, [](const uint16_t &val) { return std::to_string(val); });
            device.second->topByPackets.topDstPort.to_prometheus(out, device_labels, [](const uint16_t &val) { return std::to_string(val); });
            device.second->topByPackets.topSrcIPandPort.to_prometheus(out, device_labels);
            device.second->topByPackets.topDstIPandPort.to_prometheus(out, device_labels);
            if (group_enabled(group::FlowMetrics::Conversations)) {
                device.second->topByPackets.topConversations.to_prometheus(out, device_labels);
            }
            device.second->topByPackets.topInIfIndex.to_prometheus(out, device_labels, [](const uint32_t &val) { return std::to_string(val); });
            device.second->topByPackets.topOutIfIndex.to_prometheus(out, device_labels, [](const uint32_t &val) { return std::to_string(val); });
            if (group_enabled(group::FlowMetrics::TopGeo)) {
                device.second->topByPackets.topGeoLoc.to_prometheus(out, device_labels);
                device.second->topByPackets.topASN.to_prometheus(out, device_labels);
            }
        }
    }
}

void FlowMetricsBucket::to_json(json &j) const
{
    std::shared_lock r_lock(_mutex);

    if (group_enabled(group::FlowMetrics::Counters)) {
        _counters.filtered.to_json(j);
        _counters.total.to_json(j);
    }

    for (const auto &device : _devices_metrics) {
        auto deviceId = device.first;
        DeviceEnrich *dev{nullptr};
        if (_enrich_data) {
            auto it = _enrich_data->find(deviceId);
            if (it != _enrich_data->end()) {
                dev = &it->second;
                deviceId = it->second.name;
            }
        }
        if (_concat_if) {
            if (auto it = _concat_if->find(device.first); (it != _concat_if->end()) && !it->second.empty()) {
                deviceId += "|" + it->second;
            } else {
                deviceId += "|" + _concat_if->at("default");
            }
        }

        if (group_enabled(group::FlowMetrics::Counters)) {
            device.second->counters.UDP.to_json(j["devices"][deviceId]);
            device.second->counters.TCP.to_json(j["devices"][deviceId]);
            device.second->counters.OtherL4.to_json(j["devices"][deviceId]);
            device.second->counters.IPv4.to_json(j["devices"][deviceId]);
            device.second->counters.IPv6.to_json(j["devices"][deviceId]);
            device.second->counters.filtered.to_json(j["devices"][deviceId]);
            device.second->counters.total.to_json(j["devices"][deviceId]);
        }

        if (group_enabled(group::FlowMetrics::Cardinality)) {
            if (group_enabled(group::FlowMetrics::Conversations)) {
                device.second->conversationsCard.to_json(j["devices"][deviceId]);
            }
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
            if (group_enabled(group::FlowMetrics::Conversations)) {
                device.second->topByBytes.topConversations.to_json(j["devices"][deviceId]);
            }
            device.second->topByBytes.topInIfIndex.to_json(j["devices"][deviceId], [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
            device.second->topByBytes.topOutIfIndex.to_json(j["devices"][deviceId], [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
            if (group_enabled(group::FlowMetrics::TopGeo)) {
                device.second->topByBytes.topGeoLoc.to_json(j["devices"][deviceId]);
                device.second->topByBytes.topASN.to_json(j["devices"][deviceId]);
            }
        }

        if (group_enabled(group::FlowMetrics::TopByPackets)) {
            device.second->topByPackets.topSrcIP.to_json(j["devices"][deviceId]);
            device.second->topByPackets.topDstIP.to_json(j["devices"][deviceId]);
            device.second->topByPackets.topSrcPort.to_json(j["devices"][deviceId], [](const uint16_t &val) { return std::to_string(val); });
            device.second->topByPackets.topDstPort.to_json(j["devices"][deviceId], [](const uint16_t &val) { return std::to_string(val); });
            device.second->topByPackets.topSrcIPandPort.to_json(j["devices"][deviceId]);
            device.second->topByPackets.topDstIPandPort.to_json(j["devices"][deviceId]);
            if (group_enabled(group::FlowMetrics::Conversations)) {
                device.second->topByPackets.topConversations.to_json(j["devices"][deviceId]);
            }
            device.second->topByPackets.topInIfIndex.to_json(j["devices"][deviceId], [](const uint32_t &val) { return std::to_string(val); });
            device.second->topByPackets.topOutIfIndex.to_json(j["devices"][deviceId], [](const uint32_t &val) { return std::to_string(val); });
            if (group_enabled(group::FlowMetrics::TopGeo)) {
                device.second->topByBytes.topGeoLoc.to_json(j["devices"][deviceId]);
                device.second->topByBytes.topASN.to_json(j["devices"][deviceId]);
            }
        }
    }
}

void FlowMetricsBucket::process_flow(bool deep, const FlowPacket &payload)
{
    std::unique_lock lock(_mutex);

    if (!_devices_metrics.count(payload.device_id)) {
        _devices_metrics[payload.device_id] = std::make_unique<FlowDevice>();
        _devices_metrics[payload.device_id]->set_topn_settings(_topn_count, _topn_percentile_threshold);
    }

    auto device_flow = _devices_metrics[payload.device_id].get();

    if (group_enabled(group::FlowMetrics::Counters)) {
        _counters.filtered += payload.filtered;
        device_flow->counters.filtered += payload.filtered;
    }

    for (const auto &flow : payload.flow_data) {

        if (group_enabled(group::FlowMetrics::Counters)) {
            ++_counters.total;
            ++device_flow->counters.total;

            if (flow.is_ipv6) {
                device_flow->counters.IPv6 += flow.packets;
            } else {
                device_flow->counters.IPv4 += flow.packets;
            }

            switch (flow.l4) {
            case IP_PROTOCOL::UDP:
                device_flow->counters.UDP += flow.packets;
                break;
            case IP_PROTOCOL::TCP:
                device_flow->counters.TCP += flow.packets;
                break;
            default:
                device_flow->counters.OtherL4 += flow.packets;
                break;
            }
        }

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
            _process_geo_metrics(device_flow, flow.ipv4_in, flow.payload_size, flow.packets);
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
            _process_geo_metrics(device_flow, flow.ipv6_in, flow.payload_size, flow.packets);
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
            _process_geo_metrics(device_flow, flow.ipv4_out, flow.payload_size, flow.packets);
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
            _process_geo_metrics(device_flow, flow.ipv6_out, flow.payload_size, flow.packets);
        }

        if (group_enabled(group::FlowMetrics::Conversations) && flow.src_port > 0 && flow.dst_port > 0 && !application_src.empty() && !application_dst.empty()) {
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

inline void FlowMetricsBucket::_process_geo_metrics(FlowDevice *device, const pcpp::IPv4Address &ipv4, size_t payload_size, uint32_t packets)
{
    if ((HandlerModulePlugin::asn->enabled() || HandlerModulePlugin::city->enabled()) && group_enabled(group::FlowMetrics::TopGeo)) {
        struct sockaddr_in sa4;
        if (IPv4_to_sockaddr(ipv4, &sa4)) {
            if (HandlerModulePlugin::city->enabled()) {
                if (group_enabled(group::FlowMetrics::TopByBytes)) {
                    device->topByBytes.topGeoLoc.update(HandlerModulePlugin::city->getGeoLocString(&sa4), payload_size);
                }
                if (group_enabled(group::FlowMetrics::TopByPackets)) {
                    device->topByPackets.topGeoLoc.update(HandlerModulePlugin::city->getGeoLocString(&sa4), packets);
                }
            }
            if (HandlerModulePlugin::asn->enabled()) {
                if (group_enabled(group::FlowMetrics::TopByBytes)) {
                    device->topByBytes.topASN.update(HandlerModulePlugin::asn->getASNString(&sa4), payload_size);
                }
                if (group_enabled(group::FlowMetrics::TopByPackets)) {
                    device->topByPackets.topASN.update(HandlerModulePlugin::asn->getASNString(&sa4), packets);
                }
            }
        }
    }
}

inline void FlowMetricsBucket::_process_geo_metrics(FlowDevice *device, const pcpp::IPv6Address &ipv6, size_t payload_size, uint32_t packets)
{
    if ((HandlerModulePlugin::asn->enabled() || HandlerModulePlugin::city->enabled()) && group_enabled(group::FlowMetrics::TopGeo)) {
        struct sockaddr_in6 sa6;
        if (IPv6_to_sockaddr(ipv6, &sa6)) {
            if (HandlerModulePlugin::city->enabled()) {
                if (group_enabled(group::FlowMetrics::TopByBytes)) {
                    device->topByBytes.topGeoLoc.update(HandlerModulePlugin::city->getGeoLocString(&sa6), payload_size);
                }
                if (group_enabled(group::FlowMetrics::TopByPackets)) {
                    device->topByPackets.topGeoLoc.update(HandlerModulePlugin::city->getGeoLocString(&sa6), packets);
                }
            }
            if (HandlerModulePlugin::asn->enabled()) {
                if (group_enabled(group::FlowMetrics::TopByBytes)) {
                    device->topByBytes.topASN.update(HandlerModulePlugin::asn->getASNString(&sa6), payload_size);
                }
                if (group_enabled(group::FlowMetrics::TopByPackets)) {
                    device->topByPackets.topASN.update(HandlerModulePlugin::asn->getASNString(&sa6), packets);
                }
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
