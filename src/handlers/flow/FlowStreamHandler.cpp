/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "FlowStreamHandler.h"
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
    _groups.set(group::FlowMetrics::TopIPs);
    _groups.set(group::FlowMetrics::TopPorts);
    _groups.set(group::FlowMetrics::TopIPPorts);
    _groups.set(group::FlowMetrics::ByBytes);
    _groups.set(group::FlowMetrics::ByPackets);

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

    if (!config_exists("enrichment") || !config_get<bool>("enrichment")) {
        _metrics->set_enrich_data(std::move(enrich_data));
    }

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
            _metrics->process_filtered(stamp, payload.elements.size(), ipv4.toString());
            return;
        } else if (auto ipv6 = pcpp::IPv6Address(packet.device_id); ipv6.isValid() && std::none_of(_IPv6_devices_list.begin(), _IPv6_devices_list.end(), [ipv6](const auto &item) {
                       return ipv6 == item;
                   })) {
            _metrics->process_filtered(stamp, payload.elements.size(), ipv6.toString());
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
            _metrics->process_filtered(stamp, payload.flows.size(), ipv4.toString());
            return;
        } else if (auto ipv6 = pcpp::IPv6Address(packet.device_id); ipv6.isValid() && std::none_of(_IPv6_devices_list.begin(), _IPv6_devices_list.end(), [ipv6](const auto &item) {
                       return ipv6 == item;
                   })) {
            _metrics->process_filtered(stamp, payload.flows.size(), ipv6.toString());
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
            if ((IPv4_to_sockaddr(flow.ipv4_in, &sa4) && HandlerModulePlugin::city->getGeoLoc(&sa4).location != "Unknown")
                && (IPv4_to_sockaddr(flow.ipv4_out, &sa4) && HandlerModulePlugin::city->getGeoLoc(&sa4).location != "Unknown")) {
                return true;
            }
        } else {
            struct sockaddr_in6 sa6;
            if ((IPv6_to_sockaddr(flow.ipv6_in, &sa6) && HandlerModulePlugin::city->getGeoLoc(&sa6).location != "Unknown")
                && (IPv6_to_sockaddr(flow.ipv6_out, &sa6) && HandlerModulePlugin::city->getGeoLoc(&sa6).location != "Unknown")) {
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

    for (const auto &device : other._devices_metrics) {
        const auto &deviceId = device.first;

        if (group_enabled(group::FlowMetrics::Counters)) {
            _devices_metrics[deviceId]->total += device.second->total;
            _devices_metrics[deviceId]->filtered += device.second->filtered;
        }

        if (group_enabled(group::FlowMetrics::ByBytes) && group_enabled(group::FlowMetrics::TopInterfaces)) {
            _devices_metrics[deviceId]->topInIfIndexBytes.merge(device.second->topInIfIndexBytes);
            _devices_metrics[deviceId]->topOutIfIndexBytes.merge(device.second->topOutIfIndexBytes);
        }

        if (group_enabled(group::FlowMetrics::ByPackets) && group_enabled(group::FlowMetrics::TopInterfaces)) {
            _devices_metrics[deviceId]->topInIfIndexPackets.merge(device.second->topInIfIndexPackets);
            _devices_metrics[deviceId]->topOutIfIndexPackets.merge(device.second->topOutIfIndexPackets);
        }

        for (const auto &interface : device.second->interfaces) {
            const auto &interfaceId = interface.first;
            auto int_if = _devices_metrics[deviceId]->interfaces[interfaceId].get();

            if (group_enabled(group::FlowMetrics::Cardinality)) {
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    int_if->conversationsCard.merge(interface.second->conversationsCard);
                }
                int_if->srcIPCard.merge(interface.second->srcIPCard);
                int_if->dstIPCard.merge(interface.second->dstIPCard);
                int_if->srcPortCard.merge(interface.second->srcPortCard);
                int_if->dstPortCard.merge(interface.second->dstPortCard);
            }

            if (group_enabled(group::FlowMetrics::ByBytes)) {

                if (group_enabled(group::FlowMetrics::Counters)) {
                    int_if->countersInByBytes.UDP += interface.second->countersInByBytes.UDP;
                    int_if->countersInByBytes.TCP += interface.second->countersInByBytes.TCP;
                    int_if->countersInByBytes.OtherL4 += interface.second->countersInByBytes.OtherL4;
                    int_if->countersInByBytes.IPv4 += interface.second->countersInByBytes.IPv4;
                    int_if->countersInByBytes.IPv6 += interface.second->countersInByBytes.IPv6;
                    int_if->countersInByBytes.total += interface.second->countersInByBytes.total;

                    int_if->countersOutByBytes.UDP += interface.second->countersOutByBytes.UDP;
                    int_if->countersOutByBytes.TCP += interface.second->countersOutByBytes.TCP;
                    int_if->countersOutByBytes.OtherL4 += interface.second->countersOutByBytes.OtherL4;
                    int_if->countersOutByBytes.IPv4 += interface.second->countersOutByBytes.IPv4;
                    int_if->countersOutByBytes.IPv6 += interface.second->countersOutByBytes.IPv6;
                    int_if->countersOutByBytes.total += interface.second->countersOutByBytes.total;
                }

                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    int_if->topByBytes.topInSrcIP.merge(interface.second->topByBytes.topInSrcIP);
                    int_if->topByBytes.topInDstIP.merge(interface.second->topByBytes.topInDstIP);
                    int_if->topByBytes.topOutSrcIP.merge(interface.second->topByBytes.topOutSrcIP);
                    int_if->topByBytes.topOutDstIP.merge(interface.second->topByBytes.topOutDstIP);
                }
                if (group_enabled(group::FlowMetrics::TopPorts)) {
                    int_if->topByBytes.topInSrcPort.merge(interface.second->topByBytes.topInSrcPort);
                    int_if->topByBytes.topInDstPort.merge(interface.second->topByBytes.topInDstPort);
                    int_if->topByBytes.topOutSrcPort.merge(interface.second->topByBytes.topOutSrcPort);
                    int_if->topByBytes.topOutDstPort.merge(interface.second->topByBytes.topOutDstPort);
                }
                if (group_enabled(group::FlowMetrics::TopIPPorts)) {
                    int_if->topByBytes.topInSrcIPandPort.merge(interface.second->topByBytes.topInSrcIPandPort);
                    int_if->topByBytes.topInDstIPandPort.merge(interface.second->topByBytes.topInDstIPandPort);
                    int_if->topByBytes.topOutSrcIPandPort.merge(interface.second->topByBytes.topOutSrcIPandPort);
                    int_if->topByBytes.topOutDstIPandPort.merge(interface.second->topByBytes.topOutDstIPandPort);
                }
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    int_if->topByBytes.topGeoLoc.merge(interface.second->topByBytes.topGeoLoc);
                    int_if->topByBytes.topASN.merge(interface.second->topByBytes.topASN);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    int_if->topByBytes.topConversations.merge(interface.second->topByBytes.topConversations);
                }
            }

            if (group_enabled(group::FlowMetrics::ByPackets)) {

                if (group_enabled(group::FlowMetrics::Counters)) {
                    int_if->countersInByPackets.UDP += interface.second->countersInByPackets.UDP;
                    int_if->countersInByPackets.TCP += interface.second->countersInByPackets.TCP;
                    int_if->countersInByPackets.OtherL4 += interface.second->countersInByPackets.OtherL4;
                    int_if->countersInByPackets.IPv4 += interface.second->countersInByPackets.IPv4;
                    int_if->countersInByPackets.IPv6 += interface.second->countersInByPackets.IPv6;
                    int_if->countersInByPackets.total += interface.second->countersInByPackets.total;

                    int_if->countersOutByPackets.UDP += interface.second->countersOutByPackets.UDP;
                    int_if->countersOutByPackets.TCP += interface.second->countersOutByPackets.TCP;
                    int_if->countersOutByPackets.OtherL4 += interface.second->countersOutByPackets.OtherL4;
                    int_if->countersOutByPackets.IPv4 += interface.second->countersOutByPackets.IPv4;
                    int_if->countersOutByPackets.IPv6 += interface.second->countersOutByPackets.IPv6;
                    int_if->countersOutByPackets.total += interface.second->countersOutByPackets.total;
                }

                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    int_if->topByPackets.topInSrcIP.merge(interface.second->topByPackets.topInSrcIP);
                    int_if->topByPackets.topInDstIP.merge(interface.second->topByPackets.topInDstIP);
                    int_if->topByPackets.topOutSrcIP.merge(interface.second->topByPackets.topOutSrcIP);
                    int_if->topByPackets.topOutDstIP.merge(interface.second->topByPackets.topOutDstIP);
                }
                if (group_enabled(group::FlowMetrics::TopPorts)) {
                    int_if->topByPackets.topInSrcPort.merge(interface.second->topByPackets.topInSrcPort);
                    int_if->topByPackets.topInDstPort.merge(interface.second->topByPackets.topInDstPort);
                    int_if->topByPackets.topOutSrcPort.merge(interface.second->topByPackets.topOutSrcPort);
                    int_if->topByPackets.topOutDstPort.merge(interface.second->topByPackets.topOutDstPort);
                }
                if (group_enabled(group::FlowMetrics::TopIPPorts)) {
                    int_if->topByPackets.topInSrcIPandPort.merge(interface.second->topByPackets.topInSrcIPandPort);
                    int_if->topByPackets.topInDstIPandPort.merge(interface.second->topByPackets.topInDstIPandPort);
                    int_if->topByPackets.topOutSrcIPandPort.merge(interface.second->topByPackets.topOutSrcIPandPort);
                    int_if->topByPackets.topOutDstIPandPort.merge(interface.second->topByPackets.topOutDstIPandPort);
                }
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    int_if->topByPackets.topGeoLoc.merge(interface.second->topByPackets.topGeoLoc);
                    int_if->topByPackets.topASN.merge(interface.second->topByPackets.topASN);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    int_if->topByPackets.topConversations.merge(interface.second->topByPackets.topConversations);
                }
            }
        }
    }
}

void FlowMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{
    std::shared_lock r_lock(_mutex);

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

        if (group_enabled(group::FlowMetrics::Counters)) {
            device.second->total.to_prometheus(out, device_labels);
            device.second->filtered.to_prometheus(out, device_labels);
        }

        if (group_enabled(group::FlowMetrics::ByBytes) && group_enabled(group::FlowMetrics::TopInterfaces)) {
            device.second->topInIfIndexBytes.to_prometheus(out, device_labels, [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
            device.second->topOutIfIndexBytes.to_prometheus(out, device_labels, [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
        }

        if (group_enabled(group::FlowMetrics::ByPackets) && group_enabled(group::FlowMetrics::TopInterfaces)) {
            device.second->topInIfIndexPackets.to_prometheus(out, device_labels, [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
            device.second->topOutIfIndexPackets.to_prometheus(out, device_labels, [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
        }

        for (const auto &interface : device.second->interfaces) {
            auto interface_labels = device_labels;
            std::string interfaceId = std::to_string(interface.first);
            if (dev) {
                if (auto it = dev->interfaces.find(interface.first); it != dev->interfaces.end()) {
                    interfaceId = it->second.name;
                }
            }
            interface_labels["device_interface"] = deviceId + "|" + interfaceId;

            if (group_enabled(group::FlowMetrics::Cardinality)) {
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->conversationsCard.to_prometheus(out, device_labels);
                }
                interface.second->srcIPCard.to_prometheus(out, interface_labels);
                interface.second->dstIPCard.to_prometheus(out, interface_labels);
                interface.second->srcPortCard.to_prometheus(out, interface_labels);
                interface.second->dstPortCard.to_prometheus(out, interface_labels);
            }

            if (group_enabled(group::FlowMetrics::ByBytes)) {

                if (group_enabled(group::FlowMetrics::Counters)) {
                    interface.second->countersInByBytes.UDP.to_prometheus(out, interface_labels);
                    interface.second->countersInByBytes.TCP.to_prometheus(out, interface_labels);
                    interface.second->countersInByBytes.OtherL4.to_prometheus(out, interface_labels);
                    interface.second->countersInByBytes.IPv4.to_prometheus(out, interface_labels);
                    interface.second->countersInByBytes.IPv6.to_prometheus(out, interface_labels);
                    interface.second->countersInByBytes.total.to_prometheus(out, interface_labels);

                    interface.second->countersOutByBytes.UDP.to_prometheus(out, interface_labels);
                    interface.second->countersOutByBytes.TCP.to_prometheus(out, interface_labels);
                    interface.second->countersOutByBytes.OtherL4.to_prometheus(out, interface_labels);
                    interface.second->countersOutByBytes.IPv4.to_prometheus(out, interface_labels);
                    interface.second->countersOutByBytes.IPv6.to_prometheus(out, interface_labels);
                    interface.second->countersOutByBytes.total.to_prometheus(out, interface_labels);
                }

                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    interface.second->topByBytes.topInSrcIP.to_prometheus(out, interface_labels);
                    interface.second->topByBytes.topInDstIP.to_prometheus(out, interface_labels);
                    interface.second->topByBytes.topOutSrcIP.to_prometheus(out, interface_labels);
                    interface.second->topByBytes.topOutDstIP.to_prometheus(out, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::TopPorts)) {
                    interface.second->topByBytes.topInSrcPort.to_prometheus(out, interface_labels, [](const network::IpPort &val) { return val.get_service(); });
                    interface.second->topByBytes.topInDstPort.to_prometheus(out, interface_labels, [](const network::IpPort &val) { return val.get_service(); });
                    interface.second->topByBytes.topOutSrcPort.to_prometheus(out, interface_labels, [](const network::IpPort &val) { return val.get_service(); });
                    interface.second->topByBytes.topOutDstPort.to_prometheus(out, interface_labels, [](const network::IpPort &val) { return val.get_service(); });
                }
                if (group_enabled(group::FlowMetrics::TopIPPorts)) {
                    interface.second->topByBytes.topInSrcIPandPort.to_prometheus(out, interface_labels);
                    interface.second->topByBytes.topInDstIPandPort.to_prometheus(out, interface_labels);
                    interface.second->topByBytes.topOutSrcIPandPort.to_prometheus(out, interface_labels);
                    interface.second->topByBytes.topOutDstIPandPort.to_prometheus(out, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    interface.second->topByBytes.topGeoLoc.to_prometheus(out, interface_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
                        l[key] = val.location;
                        if (!val.latitude.empty() && !val.longitude.empty()) {
                            l["lat"] = val.latitude;
                            l["lon"] = val.longitude;
                        }
                    });
                    interface.second->topByBytes.topASN.to_prometheus(out, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->topByBytes.topConversations.to_prometheus(out, interface_labels);
                }
            }

            if (group_enabled(group::FlowMetrics::ByPackets)) {

                if (group_enabled(group::FlowMetrics::Counters)) {
                    interface.second->countersInByPackets.UDP.to_prometheus(out, interface_labels);
                    interface.second->countersInByPackets.TCP.to_prometheus(out, interface_labels);
                    interface.second->countersInByPackets.OtherL4.to_prometheus(out, interface_labels);
                    interface.second->countersInByPackets.IPv4.to_prometheus(out, interface_labels);
                    interface.second->countersInByPackets.IPv6.to_prometheus(out, interface_labels);
                    interface.second->countersInByPackets.total.to_prometheus(out, interface_labels);

                    interface.second->countersOutByPackets.UDP.to_prometheus(out, interface_labels);
                    interface.second->countersOutByPackets.TCP.to_prometheus(out, interface_labels);
                    interface.second->countersOutByPackets.OtherL4.to_prometheus(out, interface_labels);
                    interface.second->countersOutByPackets.IPv4.to_prometheus(out, interface_labels);
                    interface.second->countersOutByPackets.IPv6.to_prometheus(out, interface_labels);
                    interface.second->countersOutByPackets.total.to_prometheus(out, interface_labels);
                }

                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    interface.second->topByPackets.topInSrcIP.to_prometheus(out, interface_labels);
                    interface.second->topByPackets.topInDstIP.to_prometheus(out, interface_labels);
                    interface.second->topByPackets.topOutSrcIP.to_prometheus(out, interface_labels);
                    interface.second->topByPackets.topOutDstIP.to_prometheus(out, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::TopPorts)) {
                    interface.second->topByPackets.topInSrcPort.to_prometheus(out, interface_labels, [](const network::IpPort &val) { return val.get_service(); });
                    interface.second->topByPackets.topInDstPort.to_prometheus(out, interface_labels, [](const network::IpPort &val) { return val.get_service(); });
                    interface.second->topByPackets.topOutSrcPort.to_prometheus(out, interface_labels, [](const network::IpPort &val) { return val.get_service(); });
                    interface.second->topByPackets.topOutDstPort.to_prometheus(out, interface_labels, [](const network::IpPort &val) { return val.get_service(); });
                }
                if (group_enabled(group::FlowMetrics::TopIPPorts)) {
                    interface.second->topByPackets.topInSrcIPandPort.to_prometheus(out, interface_labels);
                    interface.second->topByPackets.topInDstIPandPort.to_prometheus(out, interface_labels);
                    interface.second->topByPackets.topOutSrcIPandPort.to_prometheus(out, interface_labels);
                    interface.second->topByPackets.topOutDstIPandPort.to_prometheus(out, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    interface.second->topByPackets.topGeoLoc.to_prometheus(out, interface_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
                        l[key] = val.location;
                        if (!val.latitude.empty() && !val.longitude.empty()) {
                            l["lat"] = val.latitude;
                            l["lon"] = val.longitude;
                        }
                    });
                    interface.second->topByPackets.topASN.to_prometheus(out, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->topByPackets.topConversations.to_prometheus(out, interface_labels);
                }
            }
        }
    }
}

void FlowMetricsBucket::to_json(json &j) const
{
    std::shared_lock r_lock(_mutex);

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

        if (group_enabled(group::FlowMetrics::Counters)) {
            device.second->total.to_json(j["devices"][deviceId]);
            device.second->filtered.to_json(j["devices"][deviceId]);
        }

        if (group_enabled(group::FlowMetrics::ByBytes) && group_enabled(group::FlowMetrics::TopInterfaces)) {
            device.second->topInIfIndexBytes.to_json(j["devices"][deviceId], [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
            device.second->topOutIfIndexBytes.to_json(j["devices"][deviceId], [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
        }

        if (group_enabled(group::FlowMetrics::ByPackets) && group_enabled(group::FlowMetrics::TopInterfaces)) {
            device.second->topInIfIndexPackets.to_json(j["devices"][deviceId], [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
            device.second->topOutIfIndexPackets.to_json(j["devices"][deviceId], [dev](const uint32_t &val) {
                if (dev) {
                    if (auto it = dev->interfaces.find(val); it != dev->interfaces.end()) {
                        return it->second.name;
                    }
                }
                return std::to_string(val);
            });
        }

        for (const auto &interface : device.second->interfaces) {
            std::string interfaceId = std::to_string(interface.first);
            if (dev) {
                if (auto it = dev->interfaces.find(interface.first); it != dev->interfaces.end()) {
                    interfaceId = it->second.name;
                }
            }

            if (group_enabled(group::FlowMetrics::Cardinality)) {
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->conversationsCard.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                interface.second->srcIPCard.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                interface.second->dstIPCard.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                interface.second->srcPortCard.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                interface.second->dstPortCard.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
            }

            if (group_enabled(group::FlowMetrics::ByBytes)) {

                if (group_enabled(group::FlowMetrics::Counters)) {
                    interface.second->countersInByBytes.UDP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersInByBytes.TCP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersInByBytes.OtherL4.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersInByBytes.IPv4.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersInByBytes.IPv6.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersInByBytes.total.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);

                    interface.second->countersOutByBytes.UDP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersOutByBytes.TCP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersOutByBytes.OtherL4.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersOutByBytes.IPv4.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersOutByBytes.IPv6.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersOutByBytes.total.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }

                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    interface.second->topByBytes.topInSrcIP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->topByBytes.topInDstIP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->topByBytes.topOutSrcIP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->topByBytes.topOutSrcIP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                if (group_enabled(group::FlowMetrics::TopPorts)) {
                    interface.second->topByBytes.topInSrcPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](const network::IpPort &val) { return val.get_service(); });
                    interface.second->topByBytes.topInDstPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](const network::IpPort &val) { return val.get_service(); });
                    interface.second->topByBytes.topOutSrcPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](const network::IpPort &val) { return val.get_service(); });
                    interface.second->topByBytes.topOutDstPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](const network::IpPort &val) { return val.get_service(); });
                }
                if (group_enabled(group::FlowMetrics::TopIPPorts)) {
                    interface.second->topByBytes.topInSrcIPandPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->topByBytes.topInDstIPandPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->topByBytes.topOutSrcIPandPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->topByBytes.topOutDstIPandPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    interface.second->topByBytes.topGeoLoc.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](json &j, const std::string &key, const visor::geo::City &val) {
                        j[key] = val.location;
                        if (!val.latitude.empty() && !val.longitude.empty()) {
                            j["lat"] = val.latitude;
                            j["lon"] = val.longitude;
                        }
                    });
                    interface.second->topByBytes.topASN.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->topByBytes.topConversations.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
            }

            if (group_enabled(group::FlowMetrics::ByPackets)) {

                if (group_enabled(group::FlowMetrics::Counters)) {
                    interface.second->countersInByPackets.UDP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersInByPackets.TCP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersInByPackets.OtherL4.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersInByPackets.IPv4.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersInByPackets.IPv6.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersInByPackets.total.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);

                    interface.second->countersOutByPackets.UDP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersOutByPackets.TCP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersOutByPackets.OtherL4.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersOutByPackets.IPv4.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersOutByPackets.IPv6.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->countersOutByPackets.total.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }

                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    interface.second->topByPackets.topInSrcIP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->topByPackets.topInDstIP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->topByPackets.topOutSrcIP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->topByPackets.topOutDstIP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                if (group_enabled(group::FlowMetrics::TopPorts)) {
                    interface.second->topByPackets.topInSrcPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](const network::IpPort &val) { return val.get_service(); });
                    interface.second->topByPackets.topInDstPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](const network::IpPort &val) { return val.get_service(); });
                    interface.second->topByPackets.topOutSrcPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](const network::IpPort &val) { return val.get_service(); });
                    interface.second->topByPackets.topOutDstPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](const network::IpPort &val) { return val.get_service(); });
                }
                if (group_enabled(group::FlowMetrics::TopIPPorts)) {
                    interface.second->topByPackets.topInSrcIPandPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->topByPackets.topInDstIPandPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->topByPackets.topOutSrcIPandPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    interface.second->topByPackets.topOutDstIPandPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    interface.second->topByPackets.topGeoLoc.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](json &j, const std::string &key, const visor::geo::City &val) {
                        j[key] = val.location;
                        if (!val.latitude.empty() && !val.longitude.empty()) {
                            j["lat"] = val.latitude;
                            j["lon"] = val.longitude;
                        }
                    });
                    interface.second->topByPackets.topASN.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->topByPackets.topConversations.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
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
        device_flow->filtered += payload.filtered;
    }

    for (const auto &flow : payload.flow_data) {
        if (group_enabled(group::FlowMetrics::Counters)) {
            ++device_flow->total;
        }

        if (!device_flow->interfaces.count(flow.if_in_index)) {
            device_flow->interfaces[flow.if_in_index] = std::make_unique<FlowInterface>();
            device_flow->interfaces[flow.if_in_index]->set_topn_settings(_topn_count, _topn_percentile_threshold);
        }
        if (!device_flow->interfaces.count(flow.if_out_index)) {
            device_flow->interfaces[flow.if_out_index] = std::make_unique<FlowInterface>();
            device_flow->interfaces[flow.if_out_index]->set_topn_settings(_topn_count, _topn_percentile_threshold);
        }

        auto if_in = device_flow->interfaces[flow.if_in_index].get();
        auto if_out = device_flow->interfaces[flow.if_out_index].get();

        if (group_enabled(group::FlowMetrics::Counters) && group_enabled(group::FlowMetrics::ByBytes)) {
            if_in->countersInByBytes.total += flow.payload_size;
            if_out->countersOutByBytes.total += flow.payload_size;

            if (flow.is_ipv6) {
                if_in->countersInByBytes.IPv6 += flow.payload_size;
                if_out->countersOutByBytes.IPv6 += flow.payload_size;
            } else {
                if_in->countersInByBytes.IPv4 += flow.payload_size;
                if_out->countersOutByBytes.IPv4 += flow.payload_size;
            }

            switch (flow.l4) {
            case IP_PROTOCOL::UDP:
                if_in->countersInByBytes.UDP += flow.payload_size;
                if_out->countersOutByBytes.UDP += flow.payload_size;
                break;
            case IP_PROTOCOL::TCP:
                if_in->countersInByBytes.TCP += flow.payload_size;
                if_out->countersOutByBytes.TCP += flow.payload_size;
                break;
            default:
                if_in->countersInByBytes.OtherL4 += flow.payload_size;
                if_out->countersOutByBytes.OtherL4 += flow.payload_size;
                break;
            }
        }

        if (group_enabled(group::FlowMetrics::Counters) && group_enabled(group::FlowMetrics::ByPackets)) {
            if_in->countersInByPackets.total += flow.packets;
            if_out->countersOutByPackets.total += flow.packets;

            if (flow.is_ipv6) {
                if_in->countersInByPackets.IPv6 += flow.packets;
                if_out->countersOutByPackets.IPv6 += flow.packets;
            } else {
                if_in->countersInByPackets.IPv4 += flow.packets;
                if_out->countersOutByPackets.IPv4 += flow.packets;
            }

            switch (flow.l4) {
            case IP_PROTOCOL::UDP:
                if_in->countersInByPackets.UDP += flow.packets;
                if_out->countersOutByPackets.UDP += flow.packets;
                break;
            case IP_PROTOCOL::TCP:
                if_in->countersInByPackets.TCP += flow.packets;
                if_out->countersOutByPackets.TCP += flow.packets;
                break;
            default:
                if_in->countersInByPackets.OtherL4 += flow.packets;
                if_out->countersOutByPackets.OtherL4 += flow.packets;
                break;
            }
        }

        if (!deep) {
            continue;
        }

        auto proto = network::Protocol::TCP;
        if (flow.l4 == IP_PROTOCOL::UDP) {
            proto = network::Protocol::UDP;
        }

        if (group_enabled(group::FlowMetrics::ByBytes)) {
            if (group_enabled(group::FlowMetrics::TopPorts)) {
                if (flow.src_port > 0) {
                    if_in->topByBytes.topInSrcPort.update(network::IpPort{flow.src_port, proto}, flow.payload_size);
                    if_out->topByBytes.topOutSrcPort.update(network::IpPort{flow.src_port, proto}, flow.payload_size);
                }
                if (flow.dst_port > 0) {
                    if_in->topByBytes.topInDstPort.update(network::IpPort{flow.dst_port, proto}, flow.payload_size);
                    if_out->topByBytes.topOutDstPort.update(network::IpPort{flow.dst_port, proto}, flow.payload_size);
                }
            }
            device_flow->topInIfIndexBytes.update(flow.if_in_index, flow.payload_size);
            device_flow->topOutIfIndexBytes.update(flow.if_out_index, flow.payload_size);
        }

        if (group_enabled(group::FlowMetrics::ByPackets)) {
            if (group_enabled(group::FlowMetrics::TopPorts)) {
                if (flow.src_port > 0) {
                    if_in->topByPackets.topInSrcPort.update(network::IpPort{flow.src_port, proto}, flow.packets);
                    if_out->topByPackets.topOutSrcPort.update(network::IpPort{flow.src_port, proto}, flow.packets);
                }
                if (flow.dst_port > 0) {
                    if_in->topByPackets.topInDstPort.update(network::IpPort{flow.dst_port, proto}, flow.packets);
                    if_out->topByPackets.topOutDstPort.update(network::IpPort{flow.dst_port, proto}, flow.packets);
                }
            }
            device_flow->topInIfIndexPackets.update(flow.if_in_index, flow.packets);
            device_flow->topOutIfIndexPackets.update(flow.if_out_index, flow.packets);
        }

        if (group_enabled(group::FlowMetrics::Cardinality)) {
            if (flow.src_port > 0) {
                if_in->srcPortCard.update(flow.src_port);
                if_out->srcPortCard.update(flow.src_port);
            }
            if (flow.dst_port > 0) {
                if_in->dstPortCard.update(flow.dst_port);
                if_out->dstPortCard.update(flow.dst_port);
            }
        }

        std::string application_src;
        std::string application_dst;

        if (!flow.is_ipv6 && flow.ipv4_in.isValid()) {
            if (group_enabled(group::FlowMetrics::Cardinality)) {
                if_in->srcIPCard.update(flow.ipv4_in.toInt());
                if_out->srcIPCard.update(flow.ipv4_in.toInt());
            }
            auto ip = flow.ipv4_in.toString();
            application_src = ip + ":" + std::to_string(flow.src_port);
            if (group_enabled(group::FlowMetrics::ByBytes)) {
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    if_in->topByBytes.topInSrcIP.update(ip, flow.payload_size);
                    if_out->topByBytes.topOutSrcIP.update(ip, flow.payload_size);
                }
                if ((flow.src_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
                    if_in->topByBytes.topInSrcIPandPort.update(application_src, flow.payload_size);
                    if_out->topByBytes.topOutSrcIPandPort.update(application_src, flow.payload_size);
                }
            }
            if (group_enabled(group::FlowMetrics::ByPackets)) {
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    if_in->topByPackets.topInSrcIP.update(ip, flow.packets);
                    if_out->topByPackets.topOutSrcIP.update(ip, flow.packets);
                }
                if ((flow.src_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
                    if_in->topByPackets.topInSrcIPandPort.update(application_src, flow.packets);
                    if_out->topByPackets.topOutSrcIPandPort.update(application_src, flow.packets);
                }
            }
            _process_geo_metrics(if_in, flow.ipv4_in, flow.payload_size, flow.packets);
            _process_geo_metrics(if_out, flow.ipv4_in, flow.payload_size, flow.packets);
        } else if (flow.is_ipv6 && flow.ipv6_in.isValid()) {
            if (group_enabled(group::FlowMetrics::Cardinality)) {
                if_in->srcIPCard.update(reinterpret_cast<const void *>(flow.ipv6_in.toBytes()), 16);
                if_out->srcIPCard.update(reinterpret_cast<const void *>(flow.ipv6_in.toBytes()), 16);
            }
            auto ip = flow.ipv6_in.toString();
            application_src = ip + ":" + std::to_string(flow.src_port);
            if (group_enabled(group::FlowMetrics::ByBytes)) {
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    if_in->topByBytes.topInSrcIP.update(ip, flow.payload_size);
                    if_out->topByBytes.topOutSrcIP.update(ip, flow.payload_size);
                }
                if ((flow.src_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
                    if_in->topByBytes.topInSrcIPandPort.update(application_src, flow.payload_size);
                    if_out->topByBytes.topOutSrcIPandPort.update(application_src, flow.payload_size);
                }
            }
            if (group_enabled(group::FlowMetrics::ByPackets)) {
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    if_in->topByPackets.topInSrcIP.update(ip, flow.packets);
                    if_out->topByPackets.topOutSrcIP.update(ip, flow.packets);
                }
                if ((flow.src_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
                    if_in->topByPackets.topInSrcIPandPort.update(application_src, flow.packets);
                    if_out->topByPackets.topOutSrcIPandPort.update(application_src, flow.packets);
                }
            }
            _process_geo_metrics(if_in, flow.ipv6_in, flow.payload_size, flow.packets);
            _process_geo_metrics(if_out, flow.ipv6_in, flow.payload_size, flow.packets);
        }

        if (!flow.is_ipv6 && flow.ipv4_out.isValid()) {
            if (group_enabled(group::FlowMetrics::Cardinality)) {
                if_in->dstIPCard.update(flow.ipv4_out.toInt());
                if_out->dstIPCard.update(flow.ipv4_out.toInt());
            }
            auto ip = flow.ipv4_out.toString();
            application_dst = ip + ":" + std::to_string(flow.dst_port);
            if (group_enabled(group::FlowMetrics::ByBytes)) {
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    if_in->topByBytes.topInDstIP.update(ip, flow.payload_size);
                    if_out->topByBytes.topOutDstIP.update(ip, flow.payload_size);
                }
                if ((flow.dst_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
                    if_in->topByBytes.topInDstIPandPort.update(application_dst, flow.payload_size);
                    if_out->topByBytes.topOutDstIPandPort.update(application_dst, flow.payload_size);
                }
            }
            if (group_enabled(group::FlowMetrics::ByPackets)) {
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    if_in->topByPackets.topInDstIP.update(ip, flow.packets);
                    if_out->topByPackets.topOutDstIP.update(ip, flow.packets);
                }
                if ((flow.dst_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
                    if_in->topByPackets.topInDstIPandPort.update(application_dst, flow.packets);
                    if_out->topByPackets.topOutDstIPandPort.update(application_dst, flow.packets);
                }
            }
            _process_geo_metrics(if_in, flow.ipv4_out, flow.payload_size, flow.packets);
            _process_geo_metrics(if_out, flow.ipv4_out, flow.payload_size, flow.packets);
        } else if (flow.is_ipv6 && flow.ipv6_out.isValid()) {
            if (group_enabled(group::FlowMetrics::Cardinality)) {
                if_in->dstIPCard.update(reinterpret_cast<const void *>(flow.ipv6_out.toBytes()), 16);
                if_out->dstIPCard.update(reinterpret_cast<const void *>(flow.ipv6_out.toBytes()), 16);
            }
            auto ip = flow.ipv6_in.toString();
            application_dst = ip + ":" + std::to_string(flow.dst_port);
            if (group_enabled(group::FlowMetrics::ByBytes)) {
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    if_in->topByBytes.topInDstIP.update(ip, flow.payload_size);
                    if_out->topByBytes.topOutDstIP.update(ip, flow.payload_size);
                }
                if ((flow.dst_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
                    if_in->topByBytes.topInDstIPandPort.update(application_dst, flow.payload_size);
                    if_out->topByBytes.topOutDstIPandPort.update(application_dst, flow.payload_size);
                }
            }
            if (group_enabled(group::FlowMetrics::ByPackets)) {
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    if_in->topByPackets.topInDstIP.update(ip, flow.packets);
                    if_out->topByPackets.topOutDstIP.update(ip, flow.packets);
                }
                if ((flow.dst_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
                    if_in->topByPackets.topInDstIPandPort.update(application_dst, flow.packets);
                    if_out->topByPackets.topOutDstIPandPort.update(application_dst, flow.packets);
                }
            }
            _process_geo_metrics(if_in, flow.ipv6_out, flow.payload_size, flow.packets);
            _process_geo_metrics(if_out, flow.ipv6_out, flow.payload_size, flow.packets);
        }

        if (group_enabled(group::FlowMetrics::Conversations) && flow.src_port > 0 && flow.dst_port > 0 && !application_src.empty() && !application_dst.empty()) {
            std::string conversation;
            if (application_src > application_dst) {
                conversation = application_dst + "/" + application_src;
            } else {
                conversation = application_src + "/" + application_dst;
            }
            if (group_enabled(group::FlowMetrics::Cardinality)) {
                if_in->conversationsCard.update(conversation);
                if_out->conversationsCard.update(conversation);
            }
            if (group_enabled(group::FlowMetrics::ByBytes)) {
                if_in->topByBytes.topConversations.update(conversation, flow.payload_size);
                if_out->topByBytes.topConversations.update(conversation, flow.payload_size);
            }
            if (group_enabled(group::FlowMetrics::ByPackets)) {
                if_in->topByPackets.topConversations.update(conversation, flow.packets);
                if_out->topByPackets.topConversations.update(conversation, flow.packets);
            }
        }
    }
}

inline void FlowMetricsBucket::_process_geo_metrics(FlowInterface *interface, const pcpp::IPv4Address &ipv4, size_t payload_size, uint32_t packets)
{
    if ((HandlerModulePlugin::asn->enabled() || HandlerModulePlugin::city->enabled()) && group_enabled(group::FlowMetrics::TopGeo)) {
        struct sockaddr_in sa4;
        if (IPv4_to_sockaddr(ipv4, &sa4)) {
            if (HandlerModulePlugin::city->enabled()) {
                if (group_enabled(group::FlowMetrics::ByBytes)) {
                    interface->topByBytes.topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa4), payload_size);
                }
                if (group_enabled(group::FlowMetrics::ByPackets)) {
                    interface->topByPackets.topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa4), packets);
                }
            }
            if (HandlerModulePlugin::asn->enabled()) {
                if (group_enabled(group::FlowMetrics::ByBytes)) {
                    interface->topByBytes.topASN.update(HandlerModulePlugin::asn->getASNString(&sa4), payload_size);
                }
                if (group_enabled(group::FlowMetrics::ByPackets)) {
                    interface->topByPackets.topASN.update(HandlerModulePlugin::asn->getASNString(&sa4), packets);
                }
            }
        }
    }
}

inline void FlowMetricsBucket::_process_geo_metrics(FlowInterface *interface, const pcpp::IPv6Address &ipv6, size_t payload_size, uint32_t packets)
{
    if ((HandlerModulePlugin::asn->enabled() || HandlerModulePlugin::city->enabled()) && group_enabled(group::FlowMetrics::TopGeo)) {
        struct sockaddr_in6 sa6;
        if (IPv6_to_sockaddr(ipv6, &sa6)) {
            if (HandlerModulePlugin::city->enabled()) {
                if (group_enabled(group::FlowMetrics::ByBytes)) {
                    interface->topByBytes.topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa6), payload_size);
                }
                if (group_enabled(group::FlowMetrics::ByPackets)) {
                    interface->topByPackets.topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa6), packets);
                }
            }
            if (HandlerModulePlugin::asn->enabled()) {
                if (group_enabled(group::FlowMetrics::ByBytes)) {
                    interface->topByBytes.topASN.update(HandlerModulePlugin::asn->getASNString(&sa6), payload_size);
                }
                if (group_enabled(group::FlowMetrics::ByPackets)) {
                    interface->topByPackets.topASN.update(HandlerModulePlugin::asn->getASNString(&sa6), packets);
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
