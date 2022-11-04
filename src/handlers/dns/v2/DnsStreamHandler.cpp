/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DnsStreamHandler.h"
#include "DnstapInputStream.h"
#include "HandlerModulePlugin.h"
#include "utils.h"
#include <Corrade/Utility/Debug.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wc99-extensions"
#pragma GCC diagnostic ignored "-Wpedantic"
#include <IPv4Layer.h>
#include <TimespecTimeval.h>
#pragma GCC diagnostic pop
#include "DnsAdditionalRecord.h"
#include "PublicSuffixList.h"
#include <sstream>
namespace visor::handler::dns {

thread_local DnsStreamHandler::DnsCacheData DnsStreamHandler::_cached_dns_layer;

DnsStreamHandler::DnsStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config)
    : visor::StreamMetricsHandler<DnsMetricsManager>(name, window_config)
{
    assert(proxy);
    // figure out which input event proxy we have
    _pcap_proxy = dynamic_cast<PcapInputEventProxy *>(proxy);
    _mock_proxy = dynamic_cast<MockInputEventProxy *>(proxy);
    _dnstap_proxy = dynamic_cast<DnstapInputEventProxy *>(proxy);
    if (!_pcap_proxy && !_mock_proxy && !_dnstap_proxy) {
        throw StreamHandlerException(fmt::format("DnsStreamHandler: unsupported input event proxy {}", proxy->name()));
    }
}

void DnsStreamHandler::start()
{
    if (_running) {
        return;
    }

    // default enabled groups
    _groups.set(group::DnsMetrics::In);
    _groups.set(group::DnsMetrics::Out);
    _groups.set(group::DnsMetrics::UndefinedDirection);
    _groups.set(group::DnsMetrics::Cardinality);
    _groups.set(group::DnsMetrics::Counters);
    _groups.set(group::DnsMetrics::Quantiles);
    _groups.set(group::DnsMetrics::TopQnames);
    _groups.set(group::DnsMetrics::TopRcodes);
    _groups.set(group::DnsMetrics::TopQtypes);
    process_groups(_group_defs);

    // Setup Filters
    if (config_exists("exclude_noerror") && config_get<bool>("exclude_noerror")) {
        _f_enabled.set(Filters::ExcludingRCode);
        _f_rcode = NoError;
    } else if (config_exists("only_rcode")) {
        uint64_t want_code;
        try {
            want_code = config_get<uint64_t>("only_rcode");
        } catch (const std::exception &e) {
            throw ConfigException("DnsStreamHandler: wrong value type for only_rcode filter. It should be an integer");
        }
        switch (want_code) {
        case NoError:
        case NXDomain:
        case SrvFail:
        case Refused:
            _f_enabled.set(Filters::OnlyRCode);
            _f_rcode = want_code;
            break;
        default:
            throw ConfigException("DnsStreamHandler: only_rcode filter contained an invalid/unsupported rcode");
        }
    }
    if (config_exists("only_dnssec_response") && config_get<bool>("only_dnssec_response")) {
        _f_enabled.set(Filters::OnlyDNSSECResponse);
    }
    if (config_exists("answer_count")) {
        try {
            _f_answer_count = config_get<uint64_t>("answer_count");
            _f_enabled.set(Filters::AnswerCount);
        } catch (const std::exception &e) {
            throw ConfigException("DnsStreamHandler: wrong value type for answer_count filter. It should be an integer");
        }
    }
    if (config_exists("only_qtype")) {
        _f_enabled.set(Filters::OnlyQtype);
        for (const auto &qtype : config_get<StringList>("only_qtype")) {
            if (std::all_of(qtype.begin(), qtype.end(), ::isdigit)) {
                auto value = std::stoul(qtype);
                if (QTypeNames.find(value) == QTypeNames.end()) {
                    throw ConfigException(fmt::format("DnsStreamHandler: only_qtype filter contained an invalid/unsupported qtype: {}", value));
                }
                _f_qtypes.push_back(value);
            } else {
                std::string upper_qtype{qtype};
                std::transform(upper_qtype.begin(), upper_qtype.end(), upper_qtype.begin(),
                    [](unsigned char c) { return std::toupper(c); });
                if (QTypeNumbers.find(upper_qtype) != QTypeNumbers.end()) {
                    _f_qtypes.push_back(QTypeNumbers[upper_qtype]);
                } else {
                    throw ConfigException(fmt::format("DnsStreamHandler: only_qtype filter contained an invalid/unsupported qtype: {}", qtype));
                }
            }
        }
    }
    if (config_exists("only_qname_suffix")) {
        _f_enabled.set(Filters::OnlyQNameSuffix);
        for (const auto &qname : config_get<StringList>("only_qname_suffix")) {
            // note, this currently copies the strings, meaning there could be a big list that is duplicated
            // we can work on trying to make this a string_view instead
            // we copy it out so that we don't have to hit the config mutex
            std::string qname_ci{qname};
            std::transform(qname_ci.begin(), qname_ci.end(), qname_ci.begin(),
                [](unsigned char c) { return std::tolower(c); });
            _f_qnames.emplace_back(std::move(qname_ci));
        }
    }
    if (config_exists("geoloc_notfound") && config_get<bool>("geoloc_notfound")) {
        _f_enabled.set(Filters::GeoLocNotFound);
    }
    if (config_exists("asn_notfound") && config_get<bool>("asn_notfound")) {
        _f_enabled.set(Filters::AsnNotFound);
    }
    if (config_exists("dnstap_msg_type")) {
        auto type = config_get<std::string>("dnstap_msg_type");
        try {
            auto type_pair = _dnstap_map_types.at(type);
            _f_dnstap_types.set(type_pair.first);
            _f_dnstap_types.set(type_pair.second);
            _f_enabled.set(Filters::DnstapMsgType);
        } catch (const std::exception &e) {
            std::vector<std::string> valid_types;
            for (const auto &type : _dnstap_map_types) {
                valid_types.push_back(type.first);
            }
            throw ConfigException(fmt::format("DnsStreamHandler: dnstap_msg_type contained an invalid/unsupported type. Valid types: {}", fmt::join(valid_types, ", ")));
        }
    }
    // Setup Configs
    if (config_exists("public_suffix_list") && config_get<bool>("public_suffix_list")) {
        _c_enabled.set(Configs::PublicSuffixList);
    }

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    if (_pcap_proxy) {
        _pkt_udp_connection = _pcap_proxy->udp_signal.connect(&DnsStreamHandler::process_udp_packet_cb, this);
        _start_tstamp_connection = _pcap_proxy->start_tstamp_signal.connect([this](timespec stamp) {
            set_start_tstamp(stamp);
            _event_proxy ? static_cast<PcapInputEventProxy *>(_event_proxy.get())->start_tstamp_signal(stamp) : void();
        });
        _end_tstamp_connection = _pcap_proxy->end_tstamp_signal.connect([this](timespec stamp) {
            set_end_tstamp(stamp);
            _event_proxy ? static_cast<PcapInputEventProxy *>(_event_proxy.get())->end_tstamp_signal(stamp) : void();
        });
        _tcp_start_connection = _pcap_proxy->tcp_connection_start_signal.connect(&DnsStreamHandler::tcp_connection_start_cb, this);
        _tcp_end_connection = _pcap_proxy->tcp_connection_end_signal.connect(&DnsStreamHandler::tcp_connection_end_cb, this);
        _tcp_message_connection = _pcap_proxy->tcp_message_ready_signal.connect(&DnsStreamHandler::tcp_message_ready_cb, this);
        _heartbeat_connection = _pcap_proxy->heartbeat_signal.connect([this](const timespec stamp) {
            check_period_shift(stamp);
            _event_proxy ? _event_proxy->heartbeat_signal(stamp) : void();
        });
    } else if (_dnstap_proxy) {
        _dnstap_connection = _dnstap_proxy->dnstap_signal.connect(&DnsStreamHandler::process_dnstap_cb, this);
        _heartbeat_connection = _dnstap_proxy->heartbeat_signal.connect([this](const timespec stamp) {
            check_period_shift(stamp);
            _event_proxy ? _event_proxy->heartbeat_signal(stamp) : void();
        });
    }

    _running = true;
}

void DnsStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    if (_pcap_proxy) {
        _pkt_udp_connection.disconnect();
        _start_tstamp_connection.disconnect();
        _end_tstamp_connection.disconnect();
        _tcp_start_connection.disconnect();
        _tcp_end_connection.disconnect();
        _tcp_message_connection.disconnect();
    } else if (_dnstap_proxy) {
        _dnstap_connection.disconnect();
    }
    _heartbeat_connection.disconnect();

    _running = false;
}

// callback from input module
void DnsStreamHandler::process_dnstap_cb(const dnstap::Dnstap &d, [[maybe_unused]] size_t size)
{
    if (_f_enabled[Filters::DnstapMsgType] && !_f_dnstap_types[d.message().type()]) {
        _metrics->process_dnstap(d, PacketDirection::unknown, true);
    } else {
        _metrics->process_dnstap(d, PacketDirection::unknown, false);
    }
}

// callback from input module
void DnsStreamHandler::process_udp_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp)
{
    pcpp::UdpLayer *udpLayer = payload.getLayerOfType<pcpp::UdpLayer>();
    assert(udpLayer);

    uint16_t metric_port{0};
    auto dst_port = ntohs(udpLayer->getUdpHeader()->portDst);
    auto src_port = ntohs(udpLayer->getUdpHeader()->portSrc);
    // note we want to capture metrics only when one of the ports is dns,
    // but metrics on the port which is _not_ the dns port
    if (DnsLayer::isDnsPort(dst_port)) {
        metric_port = src_port;
    } else if (DnsLayer::isDnsPort(src_port)) {
        metric_port = dst_port;
    }
    if (metric_port) {
        if (flowkey != _cached_dns_layer.flowKey || stamp.tv_sec != _cached_dns_layer.timestamp.tv_sec || stamp.tv_nsec != _cached_dns_layer.timestamp.tv_nsec) {
            _cached_dns_layer.flowKey = flowkey;
            _cached_dns_layer.timestamp = stamp;
            _cached_dns_layer.dnsLayer = std::make_unique<DnsLayer>(udpLayer, &payload);
        }
        auto dnsLayer = _cached_dns_layer.dnsLayer.get();
        if (!_filtering(*dnsLayer, dir, l3, pcpp::UDP, metric_port, stamp) && _configs(*dnsLayer)) {
            _metrics->process_dns_layer(*dnsLayer, dir, l3, pcpp::UDP, flowkey, metric_port, _static_suffix_size, stamp);
            _static_suffix_size = 0;
            // signal for chained stream handlers, if we have any
            if (_event_proxy) {
                static_cast<PcapInputEventProxy *>(_event_proxy.get())->packet_signal(payload, dir, l3, pcpp::UDP, stamp);
                static_cast<PcapInputEventProxy *>(_event_proxy.get())->udp_signal(payload, dir, l3, flowkey, stamp);
            }
        }
    }
}

void DnsTcpSessionData::receive_tcp_data(const uint8_t *data, size_t len)
{
    if (_invalid_data) {
        return;
    }

    _buffer.append(reinterpret_cast<const char *>(data), len);

    for (;;) {
        std::uint16_t size;

        // if buffer size < min DNS size, we know we need more data
        if (_buffer.size() < MIN_DNS_QUERY_SIZE + sizeof(size)) {
            break;
        }

        // dns packet size is in network byte order.
        size = static_cast<unsigned char>(_buffer[1]) | static_cast<unsigned char>(_buffer[0]) << 8;

        // if size is less than MIN_DNS_QUERY_SIZE, it is not a dns packet
        if (size < MIN_DNS_QUERY_SIZE) {
            _buffer.clear();
            _invalid_data = true;
            break;
        }

        if (_buffer.size() >= sizeof(size) + size) {
            auto dns_data = std::make_unique<uint8_t[]>(size);
            std::memcpy(dns_data.get(), _buffer.data() + sizeof(size), size);
            _buffer.erase(0, sizeof(size) + size);
            _got_msg(std::move(dns_data), size);
        } else {
            // Nope, we need more data.
            break;
        }
    }
}

void DnsStreamHandler::tcp_message_ready_cb(int8_t side, const pcpp::TcpStreamData &tcpData)
{
    auto flowKey = tcpData.getConnectionData().flowKey;

    // check if this flow already appears in the connection manager. If not add it
    auto iter = _tcp_connections.find(flowKey);

    // if not tracking connection, and it's DNS, then start tracking.
    if (iter == _tcp_connections.end()) {
        // note we want to capture metrics only when one of the ports is dns,
        // but metrics on the port which is _not_ the dns port
        uint16_t metric_port{0};
        if (DnsLayer::isDnsPort(tcpData.getConnectionData().dstPort)) {
            metric_port = tcpData.getConnectionData().srcPort;
        } else if (DnsLayer::isDnsPort(tcpData.getConnectionData().srcPort)) {
            metric_port = tcpData.getConnectionData().dstPort;
        }
        if (metric_port) {
            _tcp_connections.emplace(flowKey, TcpFlowData(tcpData.getConnectionData().srcIP.getType() == pcpp::IPAddress::IPv4AddressType, metric_port));
            iter = _tcp_connections.find(tcpData.getConnectionData().flowKey);
        } else {
            // not tracking
            return;
        }
    }

    pcpp::ProtocolType l3Type{iter->second.l3Type};
    auto port{iter->second.port};
    timespec stamp{0, 0};
    // for tcp, endTime is updated by pcpp to represent the time stamp from the latest packet in the stream
    TIMEVAL_TO_TIMESPEC(&tcpData.getConnectionData().endTime, &stamp);
    auto dir = (side == 0) ? PacketDirection::fromHost : PacketDirection::toHost;

    auto got_dns_message = [this, port, dir, l3Type, flowKey, stamp](std::unique_ptr<uint8_t[]> data, size_t size) {
        // this dummy packet prevents DnsLayer from owning and trying to free the data. it is otherwise unused by the DNS layer,
        // instead using the packet meta data we pass in
        pcpp::Packet dummy_packet;
        DnsLayer dnsLayer(data.get(), size, nullptr, &dummy_packet);
        if (!_filtering(dnsLayer, dir, l3Type, pcpp::UDP, port, stamp) && _configs(dnsLayer)) {
            _metrics->process_dns_layer(dnsLayer, dir, l3Type, pcpp::TCP, flowKey, port, _static_suffix_size, stamp);
            _static_suffix_size = 0;
        }
        // data is freed upon return
    };

    if (!iter->second.sessionData[side]) {
        iter->second.sessionData[side] = std::make_unique<DnsTcpSessionData>(got_dns_message);
    }

    iter->second.sessionData[side]->receive_tcp_data(tcpData.getData(), tcpData.getDataLength());
}

void DnsStreamHandler::tcp_connection_start_cb(const pcpp::ConnectionData &connectionData)
{
    // look for the connection
    auto iter = _tcp_connections.find(connectionData.flowKey);

    // note we want to capture metrics only when one of the ports is dns,
    // but metrics on the port which is _not_ the dns port
    uint16_t metric_port{0};
    if (DnsLayer::isDnsPort(connectionData.dstPort)) {
        metric_port = connectionData.srcPort;
    } else if (DnsLayer::isDnsPort(connectionData.srcPort)) {
        metric_port = connectionData.dstPort;
    }
    if (iter == _tcp_connections.end() && metric_port) {
        // add it to the connections
        _tcp_connections.emplace(connectionData.flowKey, TcpFlowData(connectionData.srcIP.getType() == pcpp::IPAddress::IPv4AddressType, metric_port));
    }
}

void DnsStreamHandler::tcp_connection_end_cb(const pcpp::ConnectionData &connectionData, [[maybe_unused]] pcpp::TcpReassembly::ConnectionEndReason reason)
{
    // find the connection in the connections by the flow key
    auto iter = _tcp_connections.find(connectionData.flowKey);

    // connection wasn't found, we didn't track
    if (iter == _tcp_connections.end()) {
        return;
    }

    // remove the connection from the connection manager
    _tcp_connections.erase(iter);
}
void DnsStreamHandler::set_start_tstamp(timespec stamp)
{
    _metrics->set_start_tstamp(stamp);
}
void DnsStreamHandler::set_end_tstamp(timespec stamp)
{
    _metrics->set_end_tstamp(stamp);
}
void DnsStreamHandler::info_json(json &j) const
{
    common_info_json(j);
    j[schema_key()]["xact"]["open"] = _metrics->num_open_transactions();
}

inline bool DnsStreamHandler::_filtering(DnsLayer &payload, [[maybe_unused]] PacketDirection dir, [[maybe_unused]] pcpp::ProtocolType l3, [[maybe_unused]] pcpp::ProtocolType l4, [[maybe_unused]] uint16_t port, timespec stamp)
{
    if (payload.getDnsHeader()->queryOrResponse == QR::response) {
        if (_f_enabled[Filters::ExcludingRCode] && payload.getDnsHeader()->responseCode == _f_rcode) {
            goto will_filter;
        } else if (_f_enabled[Filters::OnlyRCode] && payload.getDnsHeader()->responseCode != _f_rcode) {
            goto will_filter;
        }
        if (_f_enabled[Filters::AnswerCount] && payload.getAnswerCount() != _f_answer_count) {
            goto will_filter;
        }
        if (_f_enabled[Filters::OnlyDNSSECResponse]) {
            if (!payload.getAnswerCount()) {
                goto will_filter;
            }
            if (!payload.parseResources(false, true, true) || payload.getFirstAnswer() == nullptr) {
                goto will_filter;
            }
            bool has_ssig{false};
            auto dns_answer = payload.getFirstAnswer();
            for (size_t i = 0; i < payload.getAnswerCount(); ++i) {
                if (!dns_answer) {
                    break;
                }
                if (dns_answer->getDnsType() == DNS_TYPE_RRSIG) {
                    has_ssig = true;
                    break;
                }
                dns_answer = payload.getNextAnswer(dns_answer);
            }
            if (!has_ssig) {
                goto will_filter;
            }
        }
        if (_f_enabled[Filters::OnlyQtype]) {
            if (!payload.parseResources(true) || payload.getFirstQuery() == nullptr) {
                goto will_filter;
            }
            auto qtype = payload.getFirstQuery()->getDnsType();
            if (!std::any_of(_f_qtypes.begin(), _f_qtypes.end(), [qtype](uint16_t f_qtype) { return qtype == f_qtype; })) {
                goto will_filter;
            }
        }
    } else {
        if (_f_enabled[Filters::GeoLocNotFound]) {
            if (!HandlerModulePlugin::city->enabled() || !payload.getAdditionalRecordCount()) {
                goto will_filter;
            }
            if (!payload.parseResources(false, true, true) || payload.getFirstAdditionalRecord() == nullptr) {
                goto will_filter;
            }
            auto ecs = parse_additional_records_ecs(payload.getFirstAdditionalRecord());
            if (!ecs || ecs->client_subnet.empty() || (HandlerModulePlugin::city->getGeoLoc(ecs->client_subnet.c_str()).location != "Unknown")) {
                goto will_filter;
            }
        }
        if (_f_enabled[Filters::AsnNotFound]) {
            if (!HandlerModulePlugin::asn->enabled() || !payload.getAdditionalRecordCount()) {
                goto will_filter;
            }
            if (!payload.parseResources(false, true, true) || payload.getFirstAdditionalRecord() == nullptr) {
                goto will_filter;
            }
            auto ecs = parse_additional_records_ecs(payload.getFirstAdditionalRecord());
            if (!ecs || ecs->client_subnet.empty() || (HandlerModulePlugin::asn->getASNString(ecs->client_subnet.c_str()) != "Unknown")) {
                goto will_filter;
            }
        }
    }
    if (_f_enabled[Filters::OnlyQNameSuffix]) {
        if (!payload.parseResources(true) || payload.getFirstQuery() == nullptr) {
            goto will_filter;
        }
        std::string_view qname_ci = payload.getFirstQuery()->getNameLower();
        if (std::none_of(_f_qnames.begin(), _f_qnames.end(), [this, qname_ci](std::string fqn) {
                if (ends_with(qname_ci, fqn)) {
                    _static_suffix_size = fqn.size();
                    return true;
                }
                return false;
            })) {
            // checked the whole list and none of them matched: filter
            goto will_filter;
        }
    }

    return false;
will_filter:
    _metrics->process_filtered(stamp);
    return true;
}
inline bool DnsStreamHandler::_configs(DnsLayer &payload)
{
    // should only work if OnlyQNameSuffix is not enabled
    if (_c_enabled[Configs::PublicSuffixList] && !_f_enabled[Filters::OnlyQNameSuffix] && payload.parseResources(true) && payload.getFirstQuery() != nullptr) {
        _static_suffix_size = match_public_suffix(payload.getFirstQuery()->getNameLower());
    }

    return true;
}
void DnsMetricsBucket::specialized_merge(const AbstractMetricsBucket &o, Metric::Aggregate agg_operator)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const DnsMetricsBucket &>(o);

    // rates maintain their own thread safety

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    if (group_enabled(group::DnsMetrics::Counters)) {
        _filtered += other._filtered;
        group_enabled(group::DnsMetrics::In) ? _dns.at(PacketDirection::toHost).counters += other._dns.at(PacketDirection::toHost).counters : void();
        group_enabled(group::DnsMetrics::Out) ? _dns.at(PacketDirection::fromHost).counters += other._dns.at(PacketDirection::fromHost).counters : void();
        group_enabled(group::DnsMetrics::UndefinedDirection) ? _dns.at(PacketDirection::unknown).counters += other._dns.at(PacketDirection::unknown).counters : void();
    }

    if (group_enabled(group::DnsMetrics::Cardinality)) {
        group_enabled(group::DnsMetrics::In) ? _dns.at(PacketDirection::toHost).qnameCard.merge(other._dns.at(PacketDirection::toHost).qnameCard) : void();
        group_enabled(group::DnsMetrics::Out) ? _dns.at(PacketDirection::fromHost).qnameCard.merge(other._dns.at(PacketDirection::fromHost).qnameCard) : void();
        group_enabled(group::DnsMetrics::UndefinedDirection) ? _dns.at(PacketDirection::unknown).qnameCard.merge(other._dns.at(PacketDirection::unknown).qnameCard) : void();
    }

    if (group_enabled(group::DnsMetrics::Quantiles)) {
        group_enabled(group::DnsMetrics::In) ? _dns.at(PacketDirection::toHost).dnsTimeUs.merge(other._dns.at(PacketDirection::toHost).dnsTimeUs, agg_operator) : void();
        group_enabled(group::DnsMetrics::Out) ? _dns.at(PacketDirection::fromHost).dnsTimeUs.merge(other._dns.at(PacketDirection::fromHost).dnsTimeUs, agg_operator) : void();
        group_enabled(group::DnsMetrics::UndefinedDirection) ? _dns.at(PacketDirection::unknown).dnsTimeUs.merge(other._dns.at(PacketDirection::unknown).dnsTimeUs, agg_operator) : void();
    }

    if (group_enabled(group::DnsMetrics::TopEcs)) {
        if (group_enabled(group::DnsMetrics::In)) {
            _dns.at(PacketDirection::toHost).topGeoLocECS.merge(other._dns.at(PacketDirection::toHost).topGeoLocECS);
            _dns.at(PacketDirection::toHost).topASNECS.merge(other._dns.at(PacketDirection::toHost).topASNECS);
            _dns.at(PacketDirection::toHost).topQueryECS.merge(other._dns.at(PacketDirection::toHost).topQueryECS);
        }
        if (group_enabled(group::DnsMetrics::Out)) {
            _dns.at(PacketDirection::fromHost).topGeoLocECS.merge(other._dns.at(PacketDirection::fromHost).topGeoLocECS);
            _dns.at(PacketDirection::fromHost).topASNECS.merge(other._dns.at(PacketDirection::fromHost).topASNECS);
            _dns.at(PacketDirection::fromHost).topQueryECS.merge(other._dns.at(PacketDirection::fromHost).topQueryECS);
        }
        if (group_enabled(group::DnsMetrics::UndefinedDirection)) {
            _dns.at(PacketDirection::unknown).topGeoLocECS.merge(other._dns.at(PacketDirection::unknown).topGeoLocECS);
            _dns.at(PacketDirection::unknown).topASNECS.merge(other._dns.at(PacketDirection::unknown).topASNECS);
            _dns.at(PacketDirection::unknown).topQueryECS.merge(other._dns.at(PacketDirection::unknown).topQueryECS);
        }
    }

    if (group_enabled(group::DnsMetrics::TopRcodes)) {
        if (group_enabled(group::DnsMetrics::In)) {
            _dns.at(PacketDirection::toHost).topNX.merge(other._dns.at(PacketDirection::toHost).topNX);
            _dns.at(PacketDirection::toHost).topREFUSED.merge(other._dns.at(PacketDirection::toHost).topREFUSED);
            _dns.at(PacketDirection::toHost).topSRVFAIL.merge(other._dns.at(PacketDirection::toHost).topSRVFAIL);
            _dns.at(PacketDirection::toHost).topNODATA.merge(other._dns.at(PacketDirection::toHost).topNODATA);
            _dns.at(PacketDirection::toHost).topNOERROR.merge(other._dns.at(PacketDirection::toHost).topNOERROR);
            _dns.at(PacketDirection::toHost).topRCode.merge(other._dns.at(PacketDirection::toHost).topRCode);
        }
        if (group_enabled(group::DnsMetrics::Out)) {
            _dns.at(PacketDirection::fromHost).topNX.merge(other._dns.at(PacketDirection::fromHost).topNX);
            _dns.at(PacketDirection::fromHost).topREFUSED.merge(other._dns.at(PacketDirection::fromHost).topREFUSED);
            _dns.at(PacketDirection::fromHost).topSRVFAIL.merge(other._dns.at(PacketDirection::fromHost).topSRVFAIL);
            _dns.at(PacketDirection::fromHost).topNODATA.merge(other._dns.at(PacketDirection::fromHost).topNODATA);
            _dns.at(PacketDirection::fromHost).topNOERROR.merge(other._dns.at(PacketDirection::fromHost).topNOERROR);
            _dns.at(PacketDirection::fromHost).topRCode.merge(other._dns.at(PacketDirection::fromHost).topRCode);
        }
        if (group_enabled(group::DnsMetrics::UndefinedDirection)) {
            _dns.at(PacketDirection::unknown).topNX.merge(other._dns.at(PacketDirection::unknown).topNX);
            _dns.at(PacketDirection::unknown).topREFUSED.merge(other._dns.at(PacketDirection::unknown).topREFUSED);
            _dns.at(PacketDirection::unknown).topSRVFAIL.merge(other._dns.at(PacketDirection::unknown).topSRVFAIL);
            _dns.at(PacketDirection::unknown).topNODATA.merge(other._dns.at(PacketDirection::unknown).topNODATA);
            _dns.at(PacketDirection::unknown).topNOERROR.merge(other._dns.at(PacketDirection::unknown).topNOERROR);
            _dns.at(PacketDirection::unknown).topRCode.merge(other._dns.at(PacketDirection::unknown).topRCode);
        }
    }

    if (group_enabled(group::DnsMetrics::TopQnames)) {
        if (group_enabled(group::DnsMetrics::In)) {
            _dns.at(PacketDirection::toHost).topQname2.merge(other._dns.at(PacketDirection::toHost).topQname2);
            _dns.at(PacketDirection::toHost).topQname3.merge(other._dns.at(PacketDirection::toHost).topQname3);
            _dns.at(PacketDirection::toHost).topSlow.merge(other._dns.at(PacketDirection::toHost).topSlow);
        }
        if (group_enabled(group::DnsMetrics::Out)) {
            _dns.at(PacketDirection::fromHost).topQname2.merge(other._dns.at(PacketDirection::fromHost).topQname2);
            _dns.at(PacketDirection::fromHost).topQname3.merge(other._dns.at(PacketDirection::fromHost).topQname3);
            _dns.at(PacketDirection::fromHost).topSlow.merge(other._dns.at(PacketDirection::fromHost).topSlow);
        }
        if (group_enabled(group::DnsMetrics::UndefinedDirection)) {
            _dns.at(PacketDirection::unknown).topQname2.merge(other._dns.at(PacketDirection::toHost).topQname2);
            _dns.at(PacketDirection::unknown).topQname3.merge(other._dns.at(PacketDirection::toHost).topQname3);
            _dns.at(PacketDirection::unknown).topSlow.merge(other._dns.at(PacketDirection::unknown).topSlow);
        }
    }

    if (group_enabled(group::DnsMetrics::TopSize)) {
        if (group_enabled(group::DnsMetrics::In)) {
            _dns.at(PacketDirection::toHost).topSizedQnameResp.merge(other._dns.at(PacketDirection::toHost).topSizedQnameResp);
            _dns.at(PacketDirection::toHost).dnsRatio.merge(other._dns.at(PacketDirection::toHost).dnsRatio, agg_operator);
        }
        if (group_enabled(group::DnsMetrics::Out)) {
            _dns.at(PacketDirection::fromHost).topSizedQnameResp.merge(other._dns.at(PacketDirection::fromHost).topSizedQnameResp);
            _dns.at(PacketDirection::fromHost).dnsRatio.merge(other._dns.at(PacketDirection::fromHost).dnsRatio, agg_operator);
        }
        if (group_enabled(group::DnsMetrics::UndefinedDirection)) {
            _dns.at(PacketDirection::unknown).topSizedQnameResp.merge(other._dns.at(PacketDirection::unknown).topSizedQnameResp);
            _dns.at(PacketDirection::unknown).dnsRatio.merge(other._dns.at(PacketDirection::unknown).dnsRatio, agg_operator);
        }
    }

    if (group_enabled(group::DnsMetrics::TopPorts)) {
        group_enabled(group::DnsMetrics::In) ? _dns.at(PacketDirection::toHost).topUDPPort.merge(other._dns.at(PacketDirection::toHost).topUDPPort) : void();
        group_enabled(group::DnsMetrics::Out) ? _dns.at(PacketDirection::fromHost).topUDPPort.merge(other._dns.at(PacketDirection::fromHost).topUDPPort) : void();
        group_enabled(group::DnsMetrics::UndefinedDirection) ? _dns.at(PacketDirection::unknown).topUDPPort.merge(other._dns.at(PacketDirection::unknown).topUDPPort) : void();
    }

    if (group_enabled(group::DnsMetrics::TopQtypes)) {
        group_enabled(group::DnsMetrics::In) ? _dns.at(PacketDirection::toHost).topQType.merge(other._dns.at(PacketDirection::toHost).topQType) : void();
        group_enabled(group::DnsMetrics::Out) ? _dns.at(PacketDirection::fromHost).topQType.merge(other._dns.at(PacketDirection::fromHost).topQType) : void();
        group_enabled(group::DnsMetrics::UndefinedDirection) ? _dns.at(PacketDirection::unknown).topQType.merge(other._dns.at(PacketDirection::unknown).topQType) : void();
    }
}

void DnsMetricsBucket::to_json(json &j) const
{

    bool live_rates = !read_only() && !recorded_stream();

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_json(j, live_rates);
        num_events->to_json(j);
        num_samples->to_json(j);
    }

    std::shared_lock r_lock(_mutex);

    if (group_enabled(group::DnsMetrics::Counters)) {
        _filtered.to_json(j);
        group_enabled(group::DnsMetrics::In) ? _dns.at(PacketDirection::toHost).counters.to_json(j["in"]) : void();
        group_enabled(group::DnsMetrics::Out) ? _dns.at(PacketDirection::fromHost).counters.to_json(j["out"]) : void();
        group_enabled(group::DnsMetrics::UndefinedDirection) ? _dns.at(PacketDirection::unknown).counters.to_json(j["unknown"]) : void();
    }

    if (group_enabled(group::DnsMetrics::Cardinality)) {
        group_enabled(group::DnsMetrics::In) ? _dns.at(PacketDirection::toHost).qnameCard.to_json(j["in"]) : void();
        group_enabled(group::DnsMetrics::Out) ? _dns.at(PacketDirection::fromHost).qnameCard.to_json(j["out"]) : void();
        group_enabled(group::DnsMetrics::UndefinedDirection) ? _dns.at(PacketDirection::unknown).qnameCard.to_json(j["unknown"]) : void();
    }

    if (group_enabled(group::DnsMetrics::Quantiles)) {
        group_enabled(group::DnsMetrics::In) ? _dns.at(PacketDirection::toHost).dnsTimeUs.to_json(j["in"]) : void();
        group_enabled(group::DnsMetrics::Out) ? _dns.at(PacketDirection::fromHost).dnsTimeUs.to_json(j["out"]) : void();
        group_enabled(group::DnsMetrics::UndefinedDirection) ? _dns.at(PacketDirection::unknown).dnsTimeUs.to_json(j["unknown"]) : void();
    }

    if (group_enabled(group::DnsMetrics::TopPorts)) {
        group_enabled(group::DnsMetrics::In) ? _dns.at(PacketDirection::toHost).topUDPPort.to_json(j["in"], [](const uint16_t &val) { return std::to_string(val); }) : void();
        group_enabled(group::DnsMetrics::Out) ? _dns.at(PacketDirection::fromHost).topUDPPort.to_json(j["out"], [](const uint16_t &val) { return std::to_string(val); }) : void();
        group_enabled(group::DnsMetrics::UndefinedDirection) ? _dns.at(PacketDirection::unknown).topUDPPort.to_json(j["unknown"], [](const uint16_t &val) { return std::to_string(val); }) : void();
    }

    if (group_enabled(group::DnsMetrics::TopEcs)) {
        if (group_enabled(group::DnsMetrics::In)) {
            _dns.at(PacketDirection::toHost).topGeoLocECS.to_json(j["in"], [](json &j, const std::string &key, const visor::geo::City &val) {
                j[key] = val.location;
                if (!val.latitude.empty() && !val.longitude.empty()) {
                    j["lat"] = val.latitude;
                    j["lon"] = val.longitude;
                }
            });
            _dns.at(PacketDirection::toHost).topASNECS.to_json(j["in"]);
            _dns.at(PacketDirection::toHost).topQueryECS.to_json(j["in"]);
        }
        if (group_enabled(group::DnsMetrics::Out)) {
            _dns.at(PacketDirection::fromHost).topGeoLocECS.to_json(j["out"], [](json &j, const std::string &key, const visor::geo::City &val) {
                j[key] = val.location;
                if (!val.latitude.empty() && !val.longitude.empty()) {
                    j["lat"] = val.latitude;
                    j["lon"] = val.longitude;
                }
            });
            _dns.at(PacketDirection::fromHost).topASNECS.to_json(j["out"]);
            _dns.at(PacketDirection::fromHost).topQueryECS.to_json(j["out"]);
        }
        if (group_enabled(group::DnsMetrics::UndefinedDirection)) {
            _dns.at(PacketDirection::unknown).topGeoLocECS.to_json(j["unknown"], [](json &j, const std::string &key, const visor::geo::City &val) {
                j[key] = val.location;
                if (!val.latitude.empty() && !val.longitude.empty()) {
                    j["lat"] = val.latitude;
                    j["lon"] = val.longitude;
                }
            });
            _dns.at(PacketDirection::unknown).topASNECS.to_json(j["unknown"]);
            _dns.at(PacketDirection::unknown).topQueryECS.to_json(j["unknown"]);
        }
    }
    if (group_enabled(group::DnsMetrics::TopRcodes)) {
        if (group_enabled(group::DnsMetrics::In)) {
            _dns.at(PacketDirection::toHost).topNX.to_json(j["in"]);
            _dns.at(PacketDirection::toHost).topREFUSED.to_json(j["in"]);
            _dns.at(PacketDirection::toHost).topSRVFAIL.to_json(j["in"]);
            _dns.at(PacketDirection::toHost).topNODATA.to_json(j["in"]);
            _dns.at(PacketDirection::toHost).topNOERROR.to_json(j["in"]);
            _dns.at(PacketDirection::toHost).topRCode.to_json(j["in"], [](const uint16_t &val) {
                if (RCodeNames.find(val) != RCodeNames.end()) {
                    return RCodeNames[val];
                } else {
                    return std::to_string(val);
                }
            });
        }
        if (group_enabled(group::DnsMetrics::Out)) {
            _dns.at(PacketDirection::fromHost).topNX.to_json(j["out"]);
            _dns.at(PacketDirection::fromHost).topREFUSED.to_json(j["out"]);
            _dns.at(PacketDirection::fromHost).topSRVFAIL.to_json(j["out"]);
            _dns.at(PacketDirection::fromHost).topNODATA.to_json(j["out"]);
            _dns.at(PacketDirection::fromHost).topNOERROR.to_json(j["out"]);
            _dns.at(PacketDirection::fromHost).topRCode.to_json(j["out"], [](const uint16_t &val) {
                if (RCodeNames.find(val) != RCodeNames.end()) {
                    return RCodeNames[val];
                } else {
                    return std::to_string(val);
                }
            });
        }
        if (group_enabled(group::DnsMetrics::UndefinedDirection)) {
            _dns.at(PacketDirection::unknown).topNX.to_json(j["unknown"]);
            _dns.at(PacketDirection::unknown).topREFUSED.to_json(j["unknown"]);
            _dns.at(PacketDirection::unknown).topSRVFAIL.to_json(j["unknown"]);
            _dns.at(PacketDirection::unknown).topNODATA.to_json(j["unknown"]);
            _dns.at(PacketDirection::unknown).topNOERROR.to_json(j["unknown"]);
            _dns.at(PacketDirection::unknown).topRCode.to_json(j["unknown"], [](const uint16_t &val) {
                if (RCodeNames.find(val) != RCodeNames.end()) {
                    return RCodeNames[val];
                } else {
                    return std::to_string(val);
                }
            });
        }
    }

    if (group_enabled(group::DnsMetrics::TopQnames)) {
        if (group_enabled(group::DnsMetrics::In)) {
            _dns.at(PacketDirection::toHost).topQname2.to_json(j["in"]);
            _dns.at(PacketDirection::toHost).topQname3.to_json(j["in"]);
            _dns.at(PacketDirection::toHost).topSlow.to_json(j["in"]);
        }
        if (group_enabled(group::DnsMetrics::Out)) {
            _dns.at(PacketDirection::fromHost).topQname2.to_json(j["out"]);
            _dns.at(PacketDirection::fromHost).topQname3.to_json(j["out"]);
            _dns.at(PacketDirection::fromHost).topSlow.to_json(j["out"]);
        }
        if (group_enabled(group::DnsMetrics::UndefinedDirection)) {
            _dns.at(PacketDirection::unknown).topQname2.to_json(j["unknown"]);
            _dns.at(PacketDirection::unknown).topQname3.to_json(j["unknown"]);
            _dns.at(PacketDirection::unknown).topSlow.to_json(j["unknown"]);
        }
    }

    if (group_enabled(group::DnsMetrics::TopSize)) {
        if (group_enabled(group::DnsMetrics::In)) {
            _dns.at(PacketDirection::toHost).topSizedQnameResp.to_json(j["in"]);
            _dns.at(PacketDirection::toHost).dnsRatio.to_json(j["in"]);
        }
        if (group_enabled(group::DnsMetrics::Out)) {
            _dns.at(PacketDirection::fromHost).topSizedQnameResp.to_json(j["out"]);
            _dns.at(PacketDirection::fromHost).dnsRatio.to_json(j["out"]);
        }
        if (group_enabled(group::DnsMetrics::UndefinedDirection)) {
            _dns.at(PacketDirection::unknown).topSizedQnameResp.to_json(j["unknown"]);
            _dns.at(PacketDirection::unknown).dnsRatio.to_json(j["unknown"]);
        }
    }

    if (group_enabled(group::DnsMetrics::TopQtypes)) {
        if (group_enabled(group::DnsMetrics::In)) {
            _dns.at(PacketDirection::toHost).topQType.to_json(j["in"], [](const uint16_t &val) {
                if (QTypeNames.find(val) != QTypeNames.end()) {
                    return QTypeNames[val];
                } else {
                    return std::to_string(val);
                }
            });
        }
        if (group_enabled(group::DnsMetrics::Out)) {
            _dns.at(PacketDirection::fromHost).topQType.to_json(j["out"], [](const uint16_t &val) {
                if (QTypeNames.find(val) != QTypeNames.end()) {
                    return QTypeNames[val];
                } else {
                    return std::to_string(val);
                }
            });
        }
        if (group_enabled(group::DnsMetrics::UndefinedDirection)) {
            _dns.at(PacketDirection::unknown).topQType.to_json(j["unknown"], [](const uint16_t &val) {
                if (QTypeNames.find(val) != QTypeNames.end()) {
                    return QTypeNames[val];
                } else {
                    return std::to_string(val);
                }
            });
        }
    }
}

void DnsMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{
    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_prometheus(out, add_labels);
        num_events->to_prometheus(out, add_labels);
        num_samples->to_prometheus(out, add_labels);
    }

    std::shared_lock r_lock(_mutex);
    auto in_labels = add_labels;
    in_labels["direction"] = "in";
    auto out_labels = add_labels;
    out_labels["direction"] = "out";
    auto unk_labels = add_labels;
    in_labels["direction"] = "unknown";

    if (group_enabled(group::DnsMetrics::Counters)) {
        _filtered.to_prometheus(out, add_labels);
        group_enabled(group::DnsMetrics::In) ? _dns.at(PacketDirection::toHost).counters.to_prometheus(out, in_labels) : void();
        group_enabled(group::DnsMetrics::Out) ? _dns.at(PacketDirection::fromHost).counters.to_prometheus(out, out_labels) : void();
        group_enabled(group::DnsMetrics::UndefinedDirection) ? _dns.at(PacketDirection::unknown).counters.to_prometheus(out, unk_labels) : void();
    }

    if (group_enabled(group::DnsMetrics::Cardinality)) {
        group_enabled(group::DnsMetrics::In) ? _dns.at(PacketDirection::toHost).qnameCard.to_prometheus(out, in_labels) : void();
        group_enabled(group::DnsMetrics::Out) ? _dns.at(PacketDirection::fromHost).qnameCard.to_prometheus(out, out_labels) : void();
        group_enabled(group::DnsMetrics::UndefinedDirection) ? _dns.at(PacketDirection::unknown).qnameCard.to_prometheus(out, unk_labels) : void();
    }

    if (group_enabled(group::DnsMetrics::Quantiles)) {
        group_enabled(group::DnsMetrics::In) ? _dns.at(PacketDirection::toHost).dnsTimeUs.to_prometheus(out, in_labels) : void();
        group_enabled(group::DnsMetrics::Out) ? _dns.at(PacketDirection::fromHost).dnsTimeUs.to_prometheus(out, out_labels) : void();
        group_enabled(group::DnsMetrics::UndefinedDirection) ? _dns.at(PacketDirection::unknown).dnsTimeUs.to_prometheus(out, unk_labels) : void();
    }

    if (group_enabled(group::DnsMetrics::TopPorts)) {
        group_enabled(group::DnsMetrics::In) ? _dns.at(PacketDirection::toHost).topUDPPort.to_prometheus(out, in_labels, [](const uint16_t &val) { return std::to_string(val); }) : void();
        group_enabled(group::DnsMetrics::Out) ? _dns.at(PacketDirection::fromHost).topUDPPort.to_prometheus(out, out_labels, [](const uint16_t &val) { return std::to_string(val); }) : void();
        group_enabled(group::DnsMetrics::UndefinedDirection) ? _dns.at(PacketDirection::unknown).topUDPPort.to_prometheus(out, unk_labels, [](const uint16_t &val) { return std::to_string(val); }) : void();
    }

    if (group_enabled(group::DnsMetrics::TopEcs)) {
        if (group_enabled(group::DnsMetrics::In)) {
            _dns.at(PacketDirection::toHost).topGeoLocECS.to_prometheus(out, in_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
                l[key] = val.location;
                if (!val.latitude.empty() && !val.longitude.empty()) {
                    l["lat"] = val.latitude;
                    l["lon"] = val.longitude;
                }
            });
            _dns.at(PacketDirection::toHost).topASNECS.to_prometheus(out, in_labels);
            _dns.at(PacketDirection::toHost).topQueryECS.to_prometheus(out, in_labels);
        }
        if (group_enabled(group::DnsMetrics::Out)) {
            _dns.at(PacketDirection::fromHost).topGeoLocECS.to_prometheus(out, out_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
                l[key] = val.location;
                if (!val.latitude.empty() && !val.longitude.empty()) {
                    l["lat"] = val.latitude;
                    l["lon"] = val.longitude;
                }
            });
            _dns.at(PacketDirection::fromHost).topASNECS.to_prometheus(out, out_labels);
            _dns.at(PacketDirection::fromHost).topQueryECS.to_prometheus(out, out_labels);
        }
        if (group_enabled(group::DnsMetrics::UndefinedDirection)) {
            _dns.at(PacketDirection::unknown).topGeoLocECS.to_prometheus(out, unk_labels, [](Metric::LabelMap &l, const std::string &key, const visor::geo::City &val) {
                l[key] = val.location;
                if (!val.latitude.empty() && !val.longitude.empty()) {
                    l["lat"] = val.latitude;
                    l["lon"] = val.longitude;
                }
            });
            _dns.at(PacketDirection::unknown).topASNECS.to_prometheus(out, unk_labels);
            _dns.at(PacketDirection::unknown).topQueryECS.to_prometheus(out, unk_labels);
        }
    }

    if (group_enabled(group::DnsMetrics::TopRcodes)) {
        if (group_enabled(group::DnsMetrics::In)) {
            _dns.at(PacketDirection::toHost).topNX.to_prometheus(out, in_labels);
            _dns.at(PacketDirection::toHost).topREFUSED.to_prometheus(out, in_labels);
            _dns.at(PacketDirection::toHost).topSRVFAIL.to_prometheus(out, in_labels);
            _dns.at(PacketDirection::toHost).topNODATA.to_prometheus(out, in_labels);
            _dns.at(PacketDirection::toHost).topNOERROR.to_prometheus(out, in_labels);
            _dns.at(PacketDirection::toHost).topRCode.to_prometheus(out, in_labels, [](const uint16_t &val) {
                if (RCodeNames.find(val) != RCodeNames.end()) {
                    return RCodeNames[val];
                } else {
                    return std::to_string(val);
                }
            });
        }
        if (group_enabled(group::DnsMetrics::Out)) {
            _dns.at(PacketDirection::fromHost).topNX.to_prometheus(out, out_labels);
            _dns.at(PacketDirection::fromHost).topREFUSED.to_prometheus(out, out_labels);
            _dns.at(PacketDirection::fromHost).topSRVFAIL.to_prometheus(out, out_labels);
            _dns.at(PacketDirection::fromHost).topNODATA.to_prometheus(out, out_labels);
            _dns.at(PacketDirection::fromHost).topNOERROR.to_prometheus(out, out_labels);
            _dns.at(PacketDirection::fromHost).topRCode.to_prometheus(out, out_labels, [](const uint16_t &val) {
                if (RCodeNames.find(val) != RCodeNames.end()) {
                    return RCodeNames[val];
                } else {
                    return std::to_string(val);
                }
            });
        }
        if (group_enabled(group::DnsMetrics::UndefinedDirection)) {
            _dns.at(PacketDirection::unknown).topNX.to_prometheus(out, unk_labels);
            _dns.at(PacketDirection::unknown).topREFUSED.to_prometheus(out, unk_labels);
            _dns.at(PacketDirection::unknown).topSRVFAIL.to_prometheus(out, unk_labels);
            _dns.at(PacketDirection::unknown).topNODATA.to_prometheus(out, unk_labels);
            _dns.at(PacketDirection::unknown).topNOERROR.to_prometheus(out, unk_labels);
            _dns.at(PacketDirection::unknown).topRCode.to_prometheus(out, unk_labels, [](const uint16_t &val) {
                if (RCodeNames.find(val) != RCodeNames.end()) {
                    return RCodeNames[val];
                } else {
                    return std::to_string(val);
                }
            });
        }
    }

    if (group_enabled(group::DnsMetrics::TopQnames)) {
        if (group_enabled(group::DnsMetrics::In)) {
            _dns.at(PacketDirection::toHost).topQname2.to_prometheus(out, in_labels);
            _dns.at(PacketDirection::toHost).topQname3.to_prometheus(out, in_labels);
            _dns.at(PacketDirection::toHost).topSlow.to_prometheus(out, in_labels);
        }
        if (group_enabled(group::DnsMetrics::Out)) {
            _dns.at(PacketDirection::fromHost).topQname2.to_prometheus(out, out_labels);
            _dns.at(PacketDirection::fromHost).topQname3.to_prometheus(out, out_labels);
            _dns.at(PacketDirection::fromHost).topSlow.to_prometheus(out, out_labels);
        }
        if (group_enabled(group::DnsMetrics::UndefinedDirection)) {
            _dns.at(PacketDirection::unknown).topQname2.to_prometheus(out, unk_labels);
            _dns.at(PacketDirection::unknown).topQname3.to_prometheus(out, unk_labels);
            _dns.at(PacketDirection::unknown).topSlow.to_prometheus(out, unk_labels);
        }
    }

    if (group_enabled(group::DnsMetrics::TopSize)) {
        if (group_enabled(group::DnsMetrics::In)) {
            _dns.at(PacketDirection::toHost).topSizedQnameResp.to_prometheus(out, in_labels);
            _dns.at(PacketDirection::toHost).dnsRatio.to_prometheus(out, in_labels);
        }
        if (group_enabled(group::DnsMetrics::Out)) {
            _dns.at(PacketDirection::fromHost).topSizedQnameResp.to_prometheus(out, out_labels);
            _dns.at(PacketDirection::fromHost).dnsRatio.to_prometheus(out, out_labels);
        }
        if (group_enabled(group::DnsMetrics::UndefinedDirection)) {
            _dns.at(PacketDirection::unknown).topSizedQnameResp.to_prometheus(out, unk_labels);
            _dns.at(PacketDirection::unknown).dnsRatio.to_prometheus(out, unk_labels);
        }
    }

    if (group_enabled(group::DnsMetrics::TopQtypes)) {
        if (group_enabled(group::DnsMetrics::In)) {
            _dns.at(PacketDirection::toHost).topQType.to_prometheus(out, in_labels, [](const uint16_t &val) {
                if (QTypeNames.find(val) != QTypeNames.end()) {
                    return QTypeNames[val];
                } else {
                    return std::to_string(val);
                }
            });
        }
        if (group_enabled(group::DnsMetrics::Out)) {
            _dns.at(PacketDirection::fromHost).topQType.to_prometheus(out, out_labels, [](const uint16_t &val) {
                if (QTypeNames.find(val) != QTypeNames.end()) {
                    return QTypeNames[val];
                } else {
                    return std::to_string(val);
                }
            });
        }
        if (group_enabled(group::DnsMetrics::UndefinedDirection)) {
            _dns.at(PacketDirection::unknown).topQType.to_prometheus(out, unk_labels, [](const uint16_t &val) {
                if (QTypeNames.find(val) != QTypeNames.end()) {
                    return QTypeNames[val];
                } else {
                    return std::to_string(val);
                }
            });
        }
    }
}

void DnsMetricsBucket::new_dns_transaction(bool deep, float per90th, DnsLayer &payload, PacketDirection dir, DnsTransaction xact, pcpp::ProtocolType l3, Protocol l4, uint16_t port, size_t suffix_size)
{

    uint64_t xactTime = ((xact.totalTS.tv_sec * 1'000'000'000L) + xact.totalTS.tv_nsec) / 1'000; // nanoseconds to microseconds

    // lock for write
    std::unique_lock lock(_mutex);

    auto &data = _dns.at(dir);
    if (group_enabled(group::DnsMetrics::Counters)) {
        ++data.counters.xacts;

        if (l3 == pcpp::IPv6) {
            ++data.counters.IPv6;
        } else if (l3 == pcpp::IPv4) {
            ++data.counters.IPv4;
        }

        switch (l4) {
        case DNSTAP_UDP:
        case PCPP_UDP:
            ++data.counters.UDP;
            break;
        case DNSTAP_TCP:
        case PCPP_TCP:
            ++data.counters.TCP;
            break;
        case DNSTAP_DOT:
            ++data.counters.DOT;
            break;
        case DNSTAP_DOH:
            ++data.counters.DOH;
            break;
        case PCPP_UNKOWN:
            break;
        }

        switch (payload.getDnsHeader()->responseCode) {
        case NoError:
            ++data.counters.RNOERROR;
            if (!payload.getAnswerCount()) {
                ++data.counters.NODATA;
            }
            break;
        case SrvFail:
            ++data.counters.SRVFAIL;
            break;
        case NXDomain:
            ++data.counters.NX;
            break;
        case Refused:
            ++data.counters.REFUSED;
            break;
        }
    }

    if (!deep) {
        return;
    }

    if (group_enabled(group::DnsMetrics::Quantiles)) {
        data.dnsTimeUs.update(xactTime);
    }
    if (xact.querySize && group_enabled(group::DnsMetrics::TopSize)) {
        data.dnsRatio.update(static_cast<double>(payload.getDataLen()) / xact.querySize);
    }
    if (port && group_enabled(group::DnsMetrics::TopPorts)) {
        data.topUDPPort.update(port);
    }

    auto success = payload.parseResources(true);
    if (!success) {
        return;
    }

    if (payload.getDnsHeader()->queryOrResponse == response) {
        data.topRCode.update(payload.getDnsHeader()->responseCode);
    }

    auto query = payload.getFirstQuery();
    if (query) {

        auto name = query->getNameLower();

        if (group_enabled(group::DnsMetrics::Cardinality)) {
            data.qnameCard.update(name);
        }

        data.topQType.update(query->getDnsType());

        if (group_enabled(group::DnsMetrics::TopRcodes)) {

            switch (payload.getDnsHeader()->responseCode) {
            case SrvFail:
                data.topSRVFAIL.update(name);
                break;
            case NXDomain:
                data.topNX.update(name);
                break;
            case Refused:
                data.topREFUSED.update(name);
                break;
            case NoError:
                data.topNOERROR.update(name);
                if (!payload.getAnswerCount()) {
                    data.topNODATA.update(name);
                }
                break;
            }
        }
        group_enabled(group::DnsMetrics::TopSize) ? data.topSizedQnameResp.update(name, payload.getDataLen()) : void();

        if (group_enabled(group::DnsMetrics::TopQnames)) {
            if (per90th > 0 && xactTime >= per90th) {
                data.topSlow.update(name);
            }
            auto aggDomain = aggregateDomain(name, suffix_size);
            data.topQname2.update(std::string(aggDomain.first));
            if (aggDomain.second.size()) {
                data.topQname3.update(std::string(aggDomain.second));
            }
        }
    }

    if (group_enabled(group::DnsMetrics::TopEcs) && !xact.ecs.empty()) {
        if (group_enabled(group::DnsMetrics::Counters)) {
            ++data.counters.ECS;
        }
        data.topQueryECS.update(xact.ecs);
        if (HandlerModulePlugin::city->enabled()) {
            data.topGeoLocECS.update(HandlerModulePlugin::city->getGeoLoc(xact.ecs.c_str()));
        }
        if (HandlerModulePlugin::asn->enabled()) {
            data.topASNECS.update(HandlerModulePlugin::asn->getASNString(xact.ecs.c_str()));
        }
    }
}

void DnsMetricsBucket::process_filtered()
{
    std::unique_lock lock(_mutex);
    if (group_enabled(group::DnsMetrics::Counters)) {
        ++_filtered;
    }
}

// the general metrics manager entry point (both UDP and TCP)
void DnsMetricsManager::process_dns_layer(DnsLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowkey, uint16_t port, size_t suffix_size, timespec stamp)
{
    // base event
    new_event(stamp);

    if (payload.getDnsHeader()->queryOrResponse == QR::response) {
        // For response to match, need to switch direction
        if (dir == PacketDirection::toHost) {
            dir = PacketDirection::fromHost;
        } else if (dir == PacketDirection::fromHost) {
            dir = PacketDirection::toHost;
        }
        auto xact = _pair_manager[dir].xact_map.maybe_end_transaction(DnsXactID(flowkey, payload.getDnsHeader()->transactionID), stamp);
        if (xact.first == Result::Valid) {
            live_bucket()->new_dns_transaction(_deep_sampling_now, _pair_manager[dir].per_90th, payload, dir, xact.second, l3, static_cast<Protocol>(l4), port, suffix_size);
        } else if (xact.first == Result::TimedOut) {
            live_bucket()->inc_xact_timed_out(1, dir);
        } else {
            live_bucket()->inc_xact_orphan(1, dir);
        }
    } else {
        std::string subnet;
        if (group_enabled(group::DnsMetrics::TopEcs) && payload.getAdditionalRecordCount()) {
            auto additional = payload.getFirstAdditionalRecord();
            if (!additional) {
                payload.parseResources(false, true, true);
                additional = payload.getFirstAdditionalRecord();
            }
            if (auto ecs = parse_additional_records_ecs(additional); ecs) {
                subnet = ecs->client_subnet;
            }
        }
        _pair_manager[dir].xact_map.start_transaction(DnsXactID(flowkey, payload.getDnsHeader()->transactionID), {stamp, {0, 0}, payload.getDataLen(), subnet});
    }
}

void DnsMetricsManager::process_filtered(timespec stamp)
{
    // base event, no sample
    new_event(stamp, false);
    live_bucket()->process_filtered();
}

void DnsMetricsManager::process_dnstap(const dnstap::Dnstap &payload, PacketDirection dir, bool filtered)
{
    // dnstap message type
    auto mtype = payload.message().type();
    // set proper timestamp. use dnstap version if available, otherwise "now"
    timespec stamp;

    QR side{QR::query};
    switch (mtype) {
    case dnstap::Message_Type_CLIENT_RESPONSE:
    case dnstap::Message_Type_AUTH_RESPONSE:
    case dnstap::Message_Type_RESOLVER_RESPONSE:
        if (payload.message().has_response_time_sec()) {
            stamp.tv_sec = payload.message().response_time_sec();
            stamp.tv_nsec = payload.message().response_time_nsec();
        }
        [[fallthrough]];
    case dnstap::Message_Type_FORWARDER_RESPONSE:
    case dnstap::Message_Type_STUB_RESPONSE:
    case dnstap::Message_Type_TOOL_RESPONSE:
    case dnstap::Message_Type_UPDATE_RESPONSE:
        side = QR::response;
        break;
    case dnstap::Message_Type_CLIENT_QUERY:
    case dnstap::Message_Type_AUTH_QUERY:
    case dnstap::Message_Type_RESOLVER_QUERY:
        if (payload.message().has_query_time_sec()) {
            stamp.tv_sec = payload.message().query_time_sec();
            stamp.tv_nsec = payload.message().query_time_nsec();
        }
        break;
    default:
        // use now()
        std::timespec_get(&stamp, TIME_UTC);
    }

    if (filtered) {
        return process_filtered(stamp);
    }

    pcpp::ProtocolType l3{pcpp::UnknownProtocol};
    if (payload.message().has_socket_family()) {
        if (payload.message().socket_family() == dnstap::INET6) {
            l3 = pcpp::IPv6;
        } else if (payload.message().socket_family() == dnstap::INET) {
            l3 = pcpp::IPv4;
        }
    }
    Protocol l4{PCPP_UNKOWN};
    if (payload.message().has_socket_protocol()) {
        l4 = static_cast<Protocol>(payload.message().socket_protocol());
    }
    uint16_t port = 0;
    if (payload.message().has_query_port()) {
        port = payload.message().query_port();
    }

    // base event
    new_event(stamp);
    if (side == QR::response && payload.message().has_response_message()) {
        auto query = payload.message().response_message();
        uint8_t *buf = new uint8_t[query.size()];
        std::memcpy(buf, query.c_str(), query.size());
        DnsLayer dpayload(buf, query.size(), nullptr, nullptr);
        auto xact = _pair_manager[dir].xact_map.maybe_end_transaction(DnsXactID(dpayload.getDnsHeader()->transactionID, 2), stamp);
        if (xact.first == Result::Valid) {
            // process in the "live" bucket. this will parse the resources if we are deep sampling
            live_bucket()->new_dns_transaction(_deep_sampling_now, _pair_manager[dir].per_90th, dpayload, dir, xact.second, l3, static_cast<Protocol>(l4), port);
        } else if (xact.first == Result::TimedOut) {
            live_bucket()->inc_xact_timed_out(1, dir);
        } else {
            live_bucket()->inc_xact_orphan(1, dir);
        }
    } else if (payload.message().has_query_message()) {
        auto query = payload.message().query_message();
        uint8_t *buf = new uint8_t[query.size()];
        std::memcpy(buf, query.c_str(), query.size());
        DnsLayer dpayload(buf, query.size(), nullptr, nullptr);
        _pair_manager[dir].xact_map.start_transaction(DnsXactID(dpayload.getDnsHeader()->transactionID, 2), {stamp, {0, 0}, payload.message().query_message().size(), std::string()});
    }
}
}
