/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "FlowStreamHandler.h"
#include "HandlerModulePlugin.h"
#include <Corrade/Utility/Debug.h>
#include <fmt/format.h>
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace visor::handler::flow {

static std::pair<bool, std::vector<Ipv4Subnet>::const_iterator> match_subnet(std::vector<Ipv4Subnet> &ipv4_list, uint32_t ipv4_val)
{
    if (ipv4_val && !ipv4_list.empty()) {
        in_addr ipv4{};
        std::memcpy(&ipv4, &ipv4_val, sizeof(in_addr));
        for (std::vector<Ipv4Subnet>::const_iterator it = ipv4_list.begin(); it != ipv4_list.end(); ++it) {
            uint8_t cidr = it->cidr;
            if (cidr == 0) {
                return {true, it};
            }
            uint32_t mask = htonl((0xFFFFFFFFu) << (32 - cidr));
            if (!((ipv4.s_addr ^ it->addr.s_addr) & mask)) {
                return {true, it};
            }
        }
    }
    return {false, std::vector<Ipv4Subnet>::const_iterator()};
}

static std::pair<bool, std::vector<Ipv6Subnet>::const_iterator> match_subnet(std::vector<Ipv6Subnet> &ipv6_list, const uint8_t *ipv6_val)
{
    if (ipv6_val && !ipv6_list.empty()) {
        in6_addr ipv6{};
        std::memcpy(&ipv6, ipv6_val, sizeof(in6_addr));
        for (std::vector<Ipv6Subnet>::const_iterator it = ipv6_list.begin(); it != ipv6_list.end(); ++it) {
            uint8_t prefixLength = it->cidr;
            auto network = it->addr;
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
                return {true, it};
            }
        }
    }
    return {false, std::vector<Ipv6Subnet>::const_iterator()};
}

static void parse_host_specs(const std::vector<std::string> &host_list, std::vector<Ipv4Subnet> &ipv4_list, std::vector<Ipv6Subnet> &ipv6_list)
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
            in6_addr ipv6{};
            if (inet_pton(AF_INET6, ip.c_str(), &ipv6) != 1) {
                throw StreamHandlerException(fmt::format("invalid IPv6 address: {}", ip));
            }
            ipv6_list.push_back({ipv6, static_cast<uint8_t>(cidr_number), host});
        } else {
            if (cidr_number < 0 || cidr_number > 32) {
                throw StreamHandlerException(fmt::format("invalid CIDR: {}", host));
            }
            in_addr ipv4{};
            if (inet_pton(AF_INET, ip.c_str(), &ipv4) != 1) {
                throw StreamHandlerException(fmt::format("invalid IPv4 address: {}", ip));
            }
            ipv4_list.push_back({ipv4, static_cast<uint8_t>(cidr_number), host});
        }
    }
}

static std::string ip_summarization(const std::string &val, SummaryData *summary)
{
    if (summary) {
        pcpp::IPv4Address ipv4;
        pcpp::IPv6Address ipv6;
        if (ipv4 = pcpp::IPv4Address(val); ipv4.isValid() && match_subnet(summary->ipv4_exclude_summary, ipv4.toInt()).first) {
            return val;
        } else if (ipv6 = pcpp::IPv6Address(val); ipv6.isValid() && match_subnet(summary->ipv6_exclude_summary, ipv6.toBytes()).first) {
            return val;
        } else {
            return val;
        }
        if (summary->type == IpSummary::ByASN && HandlerModulePlugin::asn->enabled()) {
            if (ipv4.isValid()) {
                struct sockaddr_in sa4{};
                if (IPv4_to_sockaddr(ipv4, &sa4)) {
                    return HandlerModulePlugin::asn->getASNString(&sa4);
                }
            } else {
                struct sockaddr_in6 sa6{};
                if (IPv6_to_sockaddr(ipv6, &sa6)) {
                    return HandlerModulePlugin::asn->getASNString(&sa6);
                }
            }
        } else if (summary->type == IpSummary::BySubnet) {
            if (ipv4.isValid()) {
                if (auto [match, subnet] = match_subnet(summary->ipv4_summary, ipv4.toInt()); match) {
                    return subnet->str;
                }
            } else {
                if (auto [match, subnet] = match_subnet(summary->ipv6_summary, ipv6.toBytes()); match) {
                    return subnet->str;
                }
            }
        }
    }
    return val;
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

    validate_configs(_config_defs);

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

    EnrichData enrich_data;
    if (config_exists("device_map")) {
        auto devices = config_get<std::shared_ptr<Configurable>>("device_map");
        for (const auto &device : devices->get_all_keys()) {
            if (!pcpp::IPv4Address(device).isValid() && !pcpp::IPv6Address(device).isValid()) {
                throw StreamHandlerException(fmt::format("FlowHandler: 'device_map' config has an invalid device IP: {}", device));
            }
            DeviceEnrich enrich_device;
            auto device_map = devices->config_get<std::shared_ptr<Configurable>>(device);
            if (!device_map->config_exists("name")) {
                throw StreamHandlerException(fmt::format("FlowHandler: 'device_map' config with device IP {} does not have 'name' key", device));
            }
            enrich_device.name = device_map->config_get<std::string>("name");
            if (device_map->config_exists("description")) {
                enrich_device.descr = device_map->config_get<std::string>("description");
            }
            if (!device_map->config_exists("interfaces")) {
                throw StreamHandlerException(fmt::format("FlowHandler: 'device_map' config with device IP {} does not have 'interfaces' key", device));
            }
            auto interfaces = device_map->config_get<std::shared_ptr<Configurable>>("interfaces");
            for (auto const &interface : interfaces->get_all_keys()) {
                auto if_index = static_cast<uint32_t>(std::stol(interface));
                auto interface_map = interfaces->config_get<std::shared_ptr<Configurable>>(interface);
                if (!interface_map->config_exists("name")) {
                    throw StreamHandlerException(fmt::format("FlowHandler: 'device_map' config with device IP {} does not have 'name' key", device));
                }
                if (interface_map->config_exists("description")) {
                    enrich_device.interfaces[if_index] = {interface_map->config_get<std::string>("name"), interface_map->config_get<std::string>("description")};
                } else {
                    enrich_device.interfaces[if_index] = {interface_map->config_get<std::string>("name"), std::string()};
                }
            }
            enrich_data[device] = enrich_device;
        }
    }

    if (!config_exists("enrichment") || config_get<bool>("enrichment")) {
        _metrics->set_enrich_data(std::move(enrich_data));
    }

    SummaryData summary_data;
    if (config_exists("summarize_ips_by_asn") && config_get<bool>("summarize_ips_by_asn")) {
        summary_data.type = IpSummary::ByASN;
        if (config_exists("exclude_ips_from_summarization")) {
            parse_host_specs(config_get<StringList>("exclude_ips_from_summarization"), summary_data.ipv4_exclude_summary, summary_data.ipv6_exclude_summary);
        }
        _metrics->set_summary_data(std::move(summary_data));
    } else if (config_exists("subnets_for_summarization")) {
        summary_data.type = IpSummary::BySubnet;
        parse_host_specs(config_get<StringList>("subnets_for_summarization"), summary_data.ipv4_summary, summary_data.ipv6_summary);
        if (config_exists("exclude_ips_from_summarization")) {
            parse_host_specs(config_get<StringList>("exclude_ips_from_summarization"), summary_data.ipv4_exclude_summary, summary_data.ipv6_exclude_summary);
        }
        _metrics->set_summary_data(std::move(summary_data));
    }

    // Setup Filters
    if (config_exists("only_ips")) {
        parse_host_specs(config_get<StringList>("only_ips"), _only_ipv4_list, _only_ipv6_list);
        _f_enabled.set(Filters::OnlyIps);
    }

    if (config_exists("only_device_interfaces")) {
        auto devices = config_get<std::shared_ptr<Configurable>>("only_device_interfaces");
        for (const auto &device : devices->get_all_keys()) {
            if (pcpp::IPv4Address(device).isValid()) {
                _device_interfaces_list[device] = _parse_interfaces(devices->config_get<StringList>(device));
            } else if (pcpp::IPv6Address(device).isValid()) {
                _device_interfaces_list[device] = _parse_interfaces(devices->config_get<StringList>(device));
            } else {
                throw StreamHandlerException(fmt::format("FlowHandler: 'only_device_interfaces' filter has an invalid device IP: {}", device));
            }
        }
        _f_enabled.set(Filters::OnlyDeviceInterfaces);
    }

    if (config_exists("only_ports")) {
        _parse_ports(config_get<StringList>("only_ports"));
        _f_enabled.set(Filters::OnlyPorts);
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
    timespec stamp{};
    // use now()
    std::timespec_get(&stamp, TIME_UTC);

    std::string agentId;
    if (payload.agent_addr.type == SFLADDRESSTYPE_IP_V4) {
        agentId = pcpp::IPv4Address(payload.agent_addr.address.ip_v4.addr).toString();
    } else if (payload.agent_addr.type == SFLADDRESSTYPE_IP_V6) {
        agentId = pcpp::IPv6Address(payload.agent_addr.address.ip_v6.addr).toString();
    }

    FlowPacket packet(agentId, stamp);

    if (_f_enabled[Filters::OnlyDeviceInterfaces]) {
        if (auto ipv4 = pcpp::IPv4Address(packet.device_id); ipv4.isValid() && std::none_of(_device_interfaces_list.begin(), _device_interfaces_list.end(), [packet](const auto &item) {
                return packet.device_id == item.first;
            })) {
            _metrics->process_filtered(stamp, payload.elements.size(), packet.device_id);
            return;
        } else if (auto ipv6 = pcpp::IPv6Address(packet.device_id); ipv6.isValid() && std::none_of(_device_interfaces_list.begin(), _device_interfaces_list.end(), [packet](const auto &item) {
                       return packet.device_id == item.first;
                   })) {
            _metrics->process_filtered(stamp, payload.elements.size(), packet.device_id);
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

        if (!_filtering(flow, packet.device_id)) {
            packet.flow_data.push_back(flow);
        } else {
            ++packet.filtered;
        }
    }
    _metrics->process_flow(packet);
}

void FlowStreamHandler::process_netflow_cb(const std::string &senderIP, const NFSample &payload, [[maybe_unused]] size_t rawSize)
{
    timespec stamp{};
    if (payload.time_sec || payload.time_nanosec) {
        stamp.tv_sec = payload.time_sec;
        stamp.tv_nsec = payload.time_nanosec;
    } else {
        // use now()
        std::timespec_get(&stamp, TIME_UTC);
    }
    FlowPacket packet(senderIP, stamp);

    if (_f_enabled[Filters::OnlyDeviceInterfaces]) {
        if (auto ipv4 = pcpp::IPv4Address(packet.device_id); ipv4.isValid() && std::none_of(_device_interfaces_list.begin(), _device_interfaces_list.end(), [packet](const auto &item) {
                return packet.device_id == item.first;
            })) {
            _metrics->process_filtered(stamp, payload.flows.size(), packet.device_id);
            return;
        } else if (auto ipv6 = pcpp::IPv6Address(packet.device_id); ipv6.isValid() && std::none_of(_device_interfaces_list.begin(), _device_interfaces_list.end(), [packet](const auto &item) {
                       return packet.device_id == item.first;
                   })) {
            _metrics->process_filtered(stamp, payload.flows.size(), packet.device_id);
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

        if (!_filtering(flow, packet.device_id)) {
            packet.flow_data.push_back(flow);
        } else {
            ++packet.filtered;
        }
    }

    _metrics->process_flow(packet);
}

bool FlowStreamHandler::_filtering(FlowData &flow, const std::string &device_id)
{
    if (_f_enabled[Filters::OnlyIps]) {
        if (flow.is_ipv6 && !match_subnet(_only_ipv6_list, flow.ipv6_in.toBytes()).first && !match_subnet(_only_ipv6_list, flow.ipv6_out.toBytes()).first) {
            return true;
        } else if (!match_subnet(_only_ipv4_list, flow.ipv4_in.toInt()).first && !match_subnet(_only_ipv4_list, flow.ipv4_out.toInt()).first) {
            return true;
        }
    }

    if (_f_enabled[Filters::OnlyPorts] && std::none_of(_parsed_port_list.begin(), _parsed_port_list.end(), [flow](auto pair) {
            return (flow.src_port >= pair.first && flow.src_port <= pair.second) || (flow.dst_port >= pair.first && flow.dst_port <= pair.second);
        })) {
        return true;
    }
    if (_f_enabled[Filters::OnlyDeviceInterfaces]) {
        static constexpr uint8_t DEF_NO_MATCH = 2;
        uint8_t no_match{0};
        if (std::none_of(_device_interfaces_list[device_id].begin(), _device_interfaces_list[device_id].end(), [flow](auto pair) {
                return (flow.if_in_index >= pair.first && flow.if_in_index <= pair.second);
            })) {
            flow.if_in_index.reset();
            ++no_match;
        }
        if (std::none_of(_device_interfaces_list[device_id].begin(), _device_interfaces_list[device_id].end(), [flow](auto pair) {
                return (flow.if_out_index >= pair.first && flow.if_out_index <= pair.second);
            })) {
            flow.if_out_index.reset();
            ++no_match;
        }
        if (no_match == DEF_NO_MATCH) {
            return true;
        }
    }

    if (_f_enabled[Filters::GeoLocNotFound] && HandlerModulePlugin::city->enabled()) {
        if (!flow.is_ipv6) {
            struct sockaddr_in sa4{};
            if ((IPv4_to_sockaddr(flow.ipv4_in, &sa4) && HandlerModulePlugin::city->getGeoLoc(&sa4).location != "Unknown")
                && (IPv4_to_sockaddr(flow.ipv4_out, &sa4) && HandlerModulePlugin::city->getGeoLoc(&sa4).location != "Unknown")) {
                return true;
            }
        } else {
            struct sockaddr_in6 sa6{};
            if ((IPv6_to_sockaddr(flow.ipv6_in, &sa6) && HandlerModulePlugin::city->getGeoLoc(&sa6).location != "Unknown")
                && (IPv6_to_sockaddr(flow.ipv6_out, &sa6) && HandlerModulePlugin::city->getGeoLoc(&sa6).location != "Unknown")) {
                return true;
            }
        }
    }
    if (_f_enabled[Filters::AsnNotFound] && HandlerModulePlugin::asn->enabled()) {
        if (!flow.is_ipv6) {
            struct sockaddr_in sa4{};
            if ((IPv4_to_sockaddr(flow.ipv4_in, &sa4) && HandlerModulePlugin::asn->getASNString(&sa4) != "Unknown")
                && (IPv4_to_sockaddr(flow.ipv4_out, &sa4) && HandlerModulePlugin::asn->getASNString(&sa4) != "Unknown")) {
                return true;
            }
        } else {
            struct sockaddr_in6 sa6{};
            if ((IPv6_to_sockaddr(flow.ipv6_in, &sa6) && HandlerModulePlugin::asn->getASNString(&sa6) != "Unknown")
                && (IPv6_to_sockaddr(flow.ipv6_out, &sa6) && HandlerModulePlugin::asn->getASNString(&sa6) != "Unknown")) {
                return true;
            }
        }
    }
    return false;
}

void FlowStreamHandler::_parse_ports(const std::vector<std::string> &port_list)
{
    for (const auto &port : port_list) {
        try {
            auto delimiter = port.find('-');
            if (delimiter != port.npos) {
                auto first_value = std::stoul(port.substr(0, delimiter));
                auto last_value = std::stoul(port.substr(delimiter + 1));
                if (first_value > last_value) {
                    _parsed_port_list.emplace_back(last_value, first_value);
                } else {
                    _parsed_port_list.emplace_back(first_value, last_value);
                }
            } else {
                if (!std::all_of(port.begin(), port.end(), ::isdigit)) {
                    throw StreamHandlerException("is not a digit");
                };
                auto value = std::stoul(port);
                _parsed_port_list.emplace_back(value, value);
            }
        } catch ([[maybe_unused]] const std::exception &e) {
            throw StreamHandlerException(fmt::format("FlowHandler: invalid 'only_ports' filter value: {}", port));
        }
    }
}

std::vector<std::pair<uint32_t, uint32_t>> FlowStreamHandler::_parse_interfaces(const std::vector<std::string> &interface_list)
{
    std::vector<std::pair<uint32_t, uint32_t>> result;
    for (const auto &interface : interface_list) {
        try {
            if (interface == "*") {
                // accepts all interfaces
                result = {{std::numeric_limits<uint32_t>::min(), std::numeric_limits<uint32_t>::max()}};
                return result;
            }
            auto delimiter = interface.find('-');
            if (delimiter != interface.npos) {
                auto first_value = std::stoul(interface.substr(0, delimiter));
                auto last_value = std::stoul(interface.substr(delimiter + 1));
                if (first_value > last_value) {
                    result.emplace_back(last_value, first_value);
                } else {
                    result.emplace_back(first_value, last_value);
                }
            } else {
                if (!std::all_of(interface.begin(), interface.end(), ::isdigit)) {
                    throw StreamHandlerException("is not a digit");
                };
                auto value = std::stoul(interface);
                result.emplace_back(value, value);
            }
        } catch ([[maybe_unused]] const std::exception &e) {
            throw StreamHandlerException(fmt::format("FlowHandler: invalid 'only_device_interfaces' filter interface value: {}", interface));
        }
    }
    return result;
}

void FlowMetricsBucket::specialized_merge(const AbstractMetricsBucket &o, [[maybe_unused]] Metric::Aggregate agg_operator)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const FlowMetricsBucket &>(o);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    for (const auto &device : other._devices_metrics) {
        const auto &deviceId = device.first;
        if (!_devices_metrics.count(deviceId)) {
            _devices_metrics[deviceId] = std::make_unique<FlowDevice>();
            _devices_metrics[deviceId]->set_topn_settings(_topn_count, _topn_percentile_threshold);
        }

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
            if (!_devices_metrics[deviceId]->interfaces.count(interfaceId)) {
                _devices_metrics[deviceId]->interfaces[interfaceId] = std::make_unique<FlowInterface>();
                _devices_metrics[deviceId]->interfaces[interfaceId]->set_topn_settings(_topn_count, _topn_percentile_threshold);
            }

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

            for (auto &count_dir : int_if->counters) {
                if ((count_dir.first == InBytes || count_dir.first == OutBytes) && !group_enabled(group::FlowMetrics::ByBytes)) {
                    continue;
                }
                if ((count_dir.first == InPackets || count_dir.first == OutPackets) && !group_enabled(group::FlowMetrics::ByPackets)) {
                    continue;
                }
                if (group_enabled(group::FlowMetrics::Counters)) {
                    count_dir.second.UDP += interface.second->counters.at(count_dir.first).UDP;
                    count_dir.second.TCP += interface.second->counters.at(count_dir.first).TCP;
                    count_dir.second.OtherL4 += interface.second->counters.at(count_dir.first).OtherL4;
                    count_dir.second.IPv4 += interface.second->counters.at(count_dir.first).IPv4;
                    count_dir.second.IPv6 += interface.second->counters.at(count_dir.first).IPv6;
                    count_dir.second.total += interface.second->counters.at(count_dir.first).total;
                }
            }

            for (auto &top_dir : int_if->directionTopN) {
                if ((top_dir.first == InBytes || top_dir.first == OutBytes) && !group_enabled(group::FlowMetrics::ByBytes)) {
                    continue;
                }
                if ((top_dir.first == InPackets || top_dir.first == OutPackets) && !group_enabled(group::FlowMetrics::ByPackets)) {
                    continue;
                }
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    top_dir.second.topSrcIP.merge(interface.second->directionTopN.at(top_dir.first).topSrcIP);
                    top_dir.second.topDstIP.merge(interface.second->directionTopN.at(top_dir.first).topDstIP);
                }
                if (group_enabled(group::FlowMetrics::TopPorts)) {
                    top_dir.second.topSrcPort.merge(interface.second->directionTopN.at(top_dir.first).topSrcPort);
                    top_dir.second.topDstPort.merge(interface.second->directionTopN.at(top_dir.first).topDstPort);
                }
                if (group_enabled(group::FlowMetrics::TopIPPorts)) {
                    top_dir.second.topSrcIPandPort.merge(interface.second->directionTopN.at(top_dir.first).topSrcIPandPort);
                    top_dir.second.topDstIPandPort.merge(interface.second->directionTopN.at(top_dir.first).topDstIPandPort);
                }
            }

            if (group_enabled(group::FlowMetrics::ByBytes)) {
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    int_if->topN.first.topGeoLoc.merge(interface.second->topN.first.topGeoLoc);
                    int_if->topN.first.topASN.merge(interface.second->topN.first.topASN);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    int_if->topN.first.topConversations.merge(interface.second->topN.first.topConversations);
                }
            }

            if (group_enabled(group::FlowMetrics::ByPackets)) {
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    int_if->topN.second.topGeoLoc.merge(interface.second->topN.second.topGeoLoc);
                    int_if->topN.second.topASN.merge(interface.second->topN.second.topASN);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    int_if->topN.second.topConversations.merge(interface.second->topN.second.topConversations);
                }
            }
        }
    }
}

void FlowMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{
    std::shared_lock r_lock(_mutex);

    SummaryData *summary{nullptr};
    if (_summary_data && _summary_data->type != IpSummary::None) {
        summary = _summary_data;
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

            for (auto &count_dir : interface.second->counters) {
                if ((count_dir.first == InBytes || count_dir.first == OutBytes) && !group_enabled(group::FlowMetrics::ByBytes)) {
                    continue;
                }
                if ((count_dir.first == InPackets || count_dir.first == OutPackets) && !group_enabled(group::FlowMetrics::ByPackets)) {
                    continue;
                }
                if (group_enabled(group::FlowMetrics::Counters)) {
                    count_dir.second.UDP.to_prometheus(out, interface_labels);
                    count_dir.second.TCP.to_prometheus(out, interface_labels);
                    count_dir.second.OtherL4.to_prometheus(out, interface_labels);
                    count_dir.second.IPv4.to_prometheus(out, interface_labels);
                    count_dir.second.IPv6.to_prometheus(out, interface_labels);
                    count_dir.second.total.to_prometheus(out, interface_labels);
                }
            }

            for (auto &top_dir : interface.second->directionTopN) {
                if ((top_dir.first == InBytes || top_dir.first == OutBytes) && !group_enabled(group::FlowMetrics::ByBytes)) {
                    continue;
                }
                if ((top_dir.first == InPackets || top_dir.first == OutPackets) && !group_enabled(group::FlowMetrics::ByPackets)) {
                    continue;
                }
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    top_dir.second.topSrcIP.to_prometheus(out, interface_labels, [summary](const std::string &val) {
                        return ip_summarization(val, summary);
                    });
                    top_dir.second.topDstIP.to_prometheus(out, interface_labels, [summary](const std::string &val) {
                        return ip_summarization(val, summary);
                    });
                }
                if (group_enabled(group::FlowMetrics::TopPorts)) {
                    top_dir.second.topSrcPort.to_prometheus(out, interface_labels, [](const network::IpPort &val) { return val.get_service(); });
                    top_dir.second.topDstPort.to_prometheus(out, interface_labels, [](const network::IpPort &val) { return val.get_service(); });
                }
                if (group_enabled(group::FlowMetrics::TopIPPorts)) {
                    top_dir.second.topSrcIPandPort.to_prometheus(out, interface_labels);
                    top_dir.second.topDstIPandPort.to_prometheus(out, interface_labels);
                }
            }

            if (group_enabled(group::FlowMetrics::ByBytes)) {
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    interface.second->topN.first.topGeoLoc.to_prometheus(out, interface_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
                        l[key] = val.location;
                        if (!val.latitude.empty() && !val.longitude.empty()) {
                            l["lat"] = val.latitude;
                            l["lon"] = val.longitude;
                        }
                    });
                    interface.second->topN.first.topASN.to_prometheus(out, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->topN.first.topConversations.to_prometheus(out, interface_labels);
                }
            }

            if (group_enabled(group::FlowMetrics::ByPackets)) {
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    interface.second->topN.second.topGeoLoc.to_prometheus(out, interface_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
                        l[key] = val.location;
                        if (!val.latitude.empty() && !val.longitude.empty()) {
                            l["lat"] = val.latitude;
                            l["lon"] = val.longitude;
                        }
                    });
                    interface.second->topN.second.topASN.to_prometheus(out, interface_labels);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->topN.second.topConversations.to_prometheus(out, interface_labels);
                }
            }
        }
    }
}

void FlowMetricsBucket::to_json(json &j) const
{
    std::shared_lock r_lock(_mutex);

    SummaryData *summary{nullptr};
    if (_summary_data && _summary_data->type != IpSummary::None) {
        summary = _summary_data;
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

            for (auto &count_dir : interface.second->counters) {
                if ((count_dir.first == InBytes || count_dir.first == OutBytes) && !group_enabled(group::FlowMetrics::ByBytes)) {
                    continue;
                }
                if ((count_dir.first == InPackets || count_dir.first == OutPackets) && !group_enabled(group::FlowMetrics::ByPackets)) {
                    continue;
                }
                if (group_enabled(group::FlowMetrics::Counters)) {
                    count_dir.second.UDP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    count_dir.second.TCP.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    count_dir.second.OtherL4.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    count_dir.second.IPv4.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    count_dir.second.IPv6.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    count_dir.second.total.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
            }

            for (auto &top_dir : interface.second->directionTopN) {
                if ((top_dir.first == InBytes || top_dir.first == OutBytes) && !group_enabled(group::FlowMetrics::ByBytes)) {
                    continue;
                }
                if ((top_dir.first == InPackets || top_dir.first == OutPackets) && !group_enabled(group::FlowMetrics::ByPackets)) {
                    continue;
                }
                if (group_enabled(group::FlowMetrics::TopIPs)) {
                    top_dir.second.topSrcIP.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [summary](const std::string &val) {
                        return ip_summarization(val, summary);
                    });
                    top_dir.second.topDstIP.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [summary](const std::string &val) {
                        return ip_summarization(val, summary);
                    });
                }
                if (group_enabled(group::FlowMetrics::TopPorts)) {
                    top_dir.second.topSrcPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](const network::IpPort &val) { return val.get_service(); });
                    top_dir.second.topDstPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](const network::IpPort &val) { return val.get_service(); });
                }
                if (group_enabled(group::FlowMetrics::TopIPPorts)) {
                    top_dir.second.topSrcIPandPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                    top_dir.second.topDstIPandPort.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
            }

            if (group_enabled(group::FlowMetrics::ByBytes)) {
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    interface.second->topN.first.topGeoLoc.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](json &j, const std::string &key, const visor::geo::City &val) {
                        j[key] = val.location;
                        if (!val.latitude.empty() && !val.longitude.empty()) {
                            j["lat"] = val.latitude;
                            j["lon"] = val.longitude;
                        }
                    });
                    interface.second->topN.first.topASN.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->topN.first.topConversations.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
            }

            if (group_enabled(group::FlowMetrics::ByPackets)) {
                if (group_enabled(group::FlowMetrics::TopGeo)) {
                    interface.second->topN.second.topGeoLoc.to_json(j["devices"][deviceId]["interfaces"][interfaceId], [](json &j, const std::string &key, const visor::geo::City &val) {
                        j[key] = val.location;
                        if (!val.latitude.empty() && !val.longitude.empty()) {
                            j["lat"] = val.latitude;
                            j["lon"] = val.longitude;
                        }
                    });
                    interface.second->topN.second.topASN.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
                }
                if (group_enabled(group::FlowMetrics::Conversations)) {
                    interface.second->topN.second.topConversations.to_json(j["devices"][deviceId]["interfaces"][interfaceId]);
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
        if (flow.if_in_index.has_value()) {
            if (!device_flow->interfaces.count(flow.if_in_index.value())) {
                device_flow->interfaces[flow.if_in_index.value()] = std::make_unique<FlowInterface>();
                device_flow->interfaces[flow.if_in_index.value()]->set_topn_settings(_topn_count, _topn_percentile_threshold);
            }

            if (group_enabled(group::FlowMetrics::ByBytes)) {
                process_interface(deep, device_flow->interfaces[flow.if_in_index.value()].get(), flow, InBytes);
                if (deep && group_enabled(group::FlowMetrics::TopInterfaces)) {
                    device_flow->topInIfIndexBytes.update(flow.if_in_index.value(), flow.payload_size);
                }
            }
            if (group_enabled(group::FlowMetrics::ByPackets)) {
                process_interface(deep, device_flow->interfaces[flow.if_in_index.value()].get(), flow, InPackets);
                if (deep && group_enabled(group::FlowMetrics::TopInterfaces)) {
                    device_flow->topInIfIndexPackets.update(flow.if_in_index.value(), flow.packets);
                }
            }
        }

        if (flow.if_out_index.has_value()) {
            if (!device_flow->interfaces.count(flow.if_out_index.value())) {
                device_flow->interfaces[flow.if_out_index.value()] = std::make_unique<FlowInterface>();
                device_flow->interfaces[flow.if_out_index.value()]->set_topn_settings(_topn_count, _topn_percentile_threshold);
            }
            if (group_enabled(group::FlowMetrics::ByBytes)) {
                process_interface(deep, device_flow->interfaces[flow.if_out_index.value()].get(), flow, OutBytes);
                if (deep && group_enabled(group::FlowMetrics::TopInterfaces)) {
                    device_flow->topOutIfIndexBytes.update(flow.if_out_index.value(), flow.payload_size);
                }
            }
            if (group_enabled(group::FlowMetrics::ByPackets)) {
                process_interface(deep, device_flow->interfaces[flow.if_out_index.value()].get(), flow, OutPackets);
                if (deep && group_enabled(group::FlowMetrics::TopInterfaces)) {
                    device_flow->topInIfIndexBytes.update(flow.if_out_index.value(), flow.packets);
                }
            }
        }
    }
}

void FlowMetricsBucket::process_interface(bool deep, FlowInterface *iface, const FlowData &flow, FlowDirectionType type)
{
    uint64_t aggregator{0};
    switch (type) {
    case InBytes:
    case OutBytes:
        aggregator = flow.payload_size;
        break;
    case InPackets:
    case OutPackets:
        aggregator = flow.packets;
        break;
    }

    if (group_enabled(group::FlowMetrics::Counters)) {
        iface->counters.at(type).total += aggregator;

        if (flow.is_ipv6) {
            iface->counters.at(type).IPv6 += aggregator;
        } else {
            iface->counters.at(type).IPv4 += aggregator;
        }

        switch (flow.l4) {
        case IP_PROTOCOL::UDP:
            iface->counters.at(type).UDP += aggregator;
            break;
        case IP_PROTOCOL::TCP:
            iface->counters.at(type).TCP += aggregator;
            break;
        default:
            iface->counters.at(type).OtherL4 += aggregator;
            break;
        }
    }

    if (!deep) {
        return;
    }

    auto proto = network::Protocol::TCP;
    if (flow.l4 == IP_PROTOCOL::UDP) {
        proto = network::Protocol::UDP;
    }

    if (group_enabled(group::FlowMetrics::TopPorts)) {
        if (flow.src_port > 0) {
            iface->directionTopN.at(type).topSrcPort.update(network::IpPort{flow.src_port, proto}, aggregator);
        }
        if (flow.dst_port > 0) {
            iface->directionTopN.at(type).topDstPort.update(network::IpPort{flow.dst_port, proto}, aggregator);
        }
    }

    if (group_enabled(group::FlowMetrics::Cardinality)) {
        if (flow.src_port > 0) {
            iface->srcPortCard.update(flow.src_port);
        }
        if (flow.dst_port > 0) {
            iface->dstPortCard.update(flow.dst_port);
        }
    }

    std::string application_src;
    std::string application_dst;

    if (!flow.is_ipv6 && flow.ipv4_in.isValid()) {
        group_enabled(group::FlowMetrics::Cardinality) ? iface->srcIPCard.update(flow.ipv4_in.toInt()) : void();
        auto ip = flow.ipv4_in.toString();
        application_src = ip + ":" + std::to_string(flow.src_port);
        if (group_enabled(group::FlowMetrics::TopIPs)) {
            iface->directionTopN.at(type).topSrcIP.update(ip, aggregator);
        }
        if ((flow.src_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
            iface->directionTopN.at(type).topSrcIPandPort.update(application_src, aggregator);
        }
        _process_geo_metrics(iface, type, flow.ipv4_in, aggregator);
    } else if (flow.is_ipv6 && flow.ipv6_in.isValid()) {
        group_enabled(group::FlowMetrics::Cardinality) ? iface->srcIPCard.update(reinterpret_cast<const void *>(flow.ipv6_in.toBytes()), 16) : void();
        auto ip = flow.ipv6_in.toString();
        application_src = ip + ":" + std::to_string(flow.src_port);
        if (group_enabled(group::FlowMetrics::TopIPs)) {
            iface->directionTopN.at(type).topSrcIP.update(ip, aggregator);
        }
        if ((flow.src_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
            iface->directionTopN.at(type).topSrcIPandPort.update(application_src, aggregator);
        }
        _process_geo_metrics(iface, type, flow.ipv6_in, aggregator);
    }
    if (!flow.is_ipv6 && flow.ipv4_out.isValid()) {
        group_enabled(group::FlowMetrics::Cardinality) ? iface->dstIPCard.update(flow.ipv4_out.toInt()) : void();
        auto ip = flow.ipv4_out.toString();
        application_dst = ip + ":" + std::to_string(flow.dst_port);
        if (group_enabled(group::FlowMetrics::TopIPs)) {
            iface->directionTopN.at(type).topDstIP.update(ip, aggregator);
        }
        if ((flow.dst_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
            iface->directionTopN.at(type).topDstIPandPort.update(application_dst, aggregator);
        }
        _process_geo_metrics(iface, type, flow.ipv4_out, aggregator);
    } else if (flow.is_ipv6 && flow.ipv6_out.isValid()) {
        group_enabled(group::FlowMetrics::Cardinality) ? iface->dstIPCard.update(reinterpret_cast<const void *>(flow.ipv6_out.toBytes()), 16) : void();
        auto ip = flow.ipv6_in.toString();
        application_dst = ip + ":" + std::to_string(flow.dst_port);
        if (group_enabled(group::FlowMetrics::TopIPs)) {
            iface->directionTopN.at(type).topDstIP.update(ip, aggregator);
        }
        if ((flow.dst_port > 0) && group_enabled(group::FlowMetrics::TopIPPorts)) {
            iface->directionTopN.at(type).topDstIPandPort.update(application_dst, aggregator);
        }
        _process_geo_metrics(iface, type, flow.ipv6_out, aggregator);
    }

    if (group_enabled(group::FlowMetrics::Conversations) && flow.src_port > 0 && flow.dst_port > 0 && !application_src.empty() && !application_dst.empty()) {
        std::string conversation;
        if (application_src > application_dst) {
            conversation = application_dst + "/" + application_src;
        } else {
            conversation = application_src + "/" + application_dst;
        }
        if (group_enabled(group::FlowMetrics::Cardinality)) {
            iface->conversationsCard.update(conversation);
        }
        if (type == InBytes || type == OutBytes) {
            iface->topN.first.topConversations.update(conversation, aggregator);
        } else {
            iface->topN.second.topConversations.update(conversation, aggregator);
        }
    }
}

inline void FlowMetricsBucket::_process_geo_metrics(FlowInterface *interface, FlowDirectionType type, const pcpp::IPv4Address &ipv4, uint64_t aggregator)
{
    if ((HandlerModulePlugin::asn->enabled() || HandlerModulePlugin::city->enabled()) && group_enabled(group::FlowMetrics::TopGeo)) {
        struct sockaddr_in sa4{};
        if (IPv4_to_sockaddr(ipv4, &sa4)) {
            if (HandlerModulePlugin::city->enabled()) {
                if (type == InBytes || type == OutBytes) {
                    interface->topN.first.topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa4), aggregator);
                } else {
                    interface->topN.second.topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa4), aggregator);
                }
            }
            if (HandlerModulePlugin::asn->enabled()) {
                if (type == InBytes || type == OutBytes) {
                    interface->topN.first.topASN.update(HandlerModulePlugin::asn->getASNString(&sa4), aggregator);
                } else {
                    interface->topN.second.topASN.update(HandlerModulePlugin::asn->getASNString(&sa4), aggregator);
                }
            }
        }
    }
}

inline void FlowMetricsBucket::_process_geo_metrics(FlowInterface *interface, FlowDirectionType type, const pcpp::IPv6Address &ipv6, uint64_t aggregator)
{
    if ((HandlerModulePlugin::asn->enabled() || HandlerModulePlugin::city->enabled()) && group_enabled(group::FlowMetrics::TopGeo)) {
        struct sockaddr_in6 sa6{};
        if (IPv6_to_sockaddr(ipv6, &sa6)) {
            if (HandlerModulePlugin::city->enabled()) {
                if (type == InBytes || type == OutBytes) {
                    interface->topN.first.topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa6), aggregator);
                } else {
                    interface->topN.second.topGeoLoc.update(HandlerModulePlugin::city->getGeoLoc(&sa6), aggregator);
                }
            }
            if (HandlerModulePlugin::asn->enabled()) {
                if (type == InBytes || type == OutBytes) {
                    interface->topN.first.topASN.update(HandlerModulePlugin::asn->getASNString(&sa6), aggregator);
                } else {
                    interface->topN.second.topASN.update(HandlerModulePlugin::asn->getASNString(&sa6), aggregator);
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
