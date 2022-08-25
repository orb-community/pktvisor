/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DnsXactStreamHandler.h"
#include "DnstapInputStream.h"
#include "GeoDB.h"
#include "utils.h"
#include <Corrade/Utility/Debug.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wc99-extensions"
#pragma GCC diagnostic ignored "-Wpedantic"
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#pragma GCC diagnostic pop
#include "PacketUtils.h"
#include "visor_dns/DnsAdditionalRecord.h"
#include "visor_dns/PublicSuffixList.h"
#include <arpa/inet.h>
#include <sstream>
namespace visor::handler::dns {

thread_local DnsXactStreamHandler::DnsCacheData DnsXactStreamHandler::_cached_dns_layer;

DnsXactStreamHandler::DnsXactStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config)
    : visor::StreamMetricsHandler<DnsXactMetricsManager>(name, window_config)
{
    assert(proxy);
    // figure out which input event proxy we have
    _pcap_proxy = dynamic_cast<PcapInputEventProxy *>(proxy);
    _mock_proxy = dynamic_cast<MockInputEventProxy *>(proxy);
    _dnstap_proxy = dynamic_cast<DnstapInputEventProxy *>(proxy);
    if (!_pcap_proxy && !_mock_proxy && !_dnstap_proxy) {
        throw StreamHandlerException(fmt::format("DnsXactStreamHandler: unsupported input event proxy {}", proxy->name()));
    }
}

void DnsXactStreamHandler::start()
{
    if (_running) {
        return;
    }

    // default enabled groups
    _groups.set(group::xact::DnsXactMetrics::DnsTransactions);
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
            throw ConfigException("DnsXactStreamHandler: wrong value type for only_rcode filter. It should be an integer");
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
            throw ConfigException("DnsXactStreamHandler: only_rcode filter contained an invalid/unsupported rcode");
        }
        _register_predicate_filter(Filters::OnlyRCode, "only_rcode", std::to_string(_f_rcode));
    }
    if (config_exists("only_dnssec_response") && config_get<bool>("only_dnssec_response")) {
        _f_enabled.set(Filters::OnlyDNSSECResponse);
    }
    if (config_exists("answer_count")) {
        try {
            _f_answer_count = config_get<uint64_t>("answer_count");
            _f_enabled.set(Filters::AnswerCount);
        } catch (const std::exception &e) {
            throw ConfigException("DnsXactStreamHandler: wrong value type for answer_count filter. It should be an integer");
        }
    }
    if (config_exists("only_qtype")) {
        _f_enabled.set(Filters::OnlyQtype);
        for (const auto &qtype : config_get<StringList>("only_qtype")) {
            if (std::all_of(qtype.begin(), qtype.end(), ::isdigit)) {
                auto value = std::stoul(qtype);
                if (QTypeNames.find(value) == QTypeNames.end()) {
                    throw ConfigException(fmt::format("DnsXactStreamHandler: only_qtype filter contained an invalid/unsupported qtype: {}", value));
                }
                _f_qtypes.push_back(value);
            } else {
                std::string upper_qtype{qtype};
                std::transform(upper_qtype.begin(), upper_qtype.end(), upper_qtype.begin(),
                    [](unsigned char c) { return std::toupper(c); });
                if (QTypeNumbers.find(upper_qtype) != QTypeNumbers.end()) {
                    _f_qtypes.push_back(QTypeNumbers[upper_qtype]);
                } else {
                    throw ConfigException(fmt::format("DnsXactStreamHandler: only_qtype filter contained an invalid/unsupported qtype: {}", qtype));
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
            throw ConfigException(fmt::format("DnsXactStreamHandler: dnstap_msg_type contained an invalid/unsupported type. Valid types: {}", fmt::join(valid_types, ", ")));
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
        if (!_using_predicate_signals) {
            _pkt_udp_connection = _pcap_proxy->udp_signal.connect(&DnsXactStreamHandler::process_udp_packet_cb, this);
        }
        _start_tstamp_connection = _pcap_proxy->start_tstamp_signal.connect([this](timespec stamp) {
            set_start_tstamp(stamp);
            _event_proxy ? static_cast<PcapInputEventProxy *>(_event_proxy.get())->start_tstamp_signal(stamp) : void();
        });
        _end_tstamp_connection = _pcap_proxy->end_tstamp_signal.connect([this](timespec stamp) {
            set_end_tstamp(stamp);
            _event_proxy ? static_cast<PcapInputEventProxy *>(_event_proxy.get())->end_tstamp_signal(stamp) : void();
        });
        _tcp_start_connection = _pcap_proxy->tcp_connection_start_signal.connect(&DnsXactStreamHandler::tcp_connection_start_cb, this);
        _tcp_end_connection = _pcap_proxy->tcp_connection_end_signal.connect(&DnsXactStreamHandler::tcp_connection_end_cb, this);
        _tcp_message_connection = _pcap_proxy->tcp_message_ready_signal.connect(&DnsXactStreamHandler::tcp_message_ready_cb, this);
        _heartbeat_connection = _pcap_proxy->heartbeat_signal.connect([this](const timespec stamp) {
            check_period_shift(stamp);
            _event_proxy ? _event_proxy->heartbeat_signal(stamp) : void();
        });
    } else if (_dnstap_proxy) {
        _dnstap_connection = _dnstap_proxy->dnstap_signal.connect(&DnsXactStreamHandler::process_dnstap_cb, this);
        _heartbeat_connection = _dnstap_proxy->heartbeat_signal.connect([this](const timespec stamp) {
            check_period_shift(stamp);
            _event_proxy ? _event_proxy->heartbeat_signal(stamp) : void();
        });
    }

    _running = true;
}

void DnsXactStreamHandler::stop()
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
        if (_using_predicate_signals) {
            _pcap_proxy->unregister_udp_predicate_signal(name());
        }
    } else if (_dnstap_proxy) {
        _dnstap_connection.disconnect();
    }
    _heartbeat_connection.disconnect();

    _running = false;
}

// callback from input module
void DnsXactStreamHandler::process_dnstap_cb(const dnstap::Dnstap &d, [[maybe_unused]] size_t size)
{
    if (_f_enabled[Filters::DnstapMsgType] && !_f_dnstap_types[d.message().type()]) {
        _metrics->process_dnstap(d, true);
    } else {
        _metrics->process_dnstap(d, false);
    }
}

// callback from input module
void DnsXactStreamHandler::process_udp_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp)
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
        if (!_filtering(*dnsLayer, dir, flowkey, stamp) && _configs(*dnsLayer)) {
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

void DnsXactTcpSessionData::receive_tcp_data(const uint8_t *data, size_t len)
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

void DnsXactStreamHandler::tcp_message_ready_cb(int8_t side, const pcpp::TcpStreamData &tcpData)
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
        if (!_filtering(dnsLayer, dir, flowKey, stamp) && _configs(dnsLayer)) {
            _metrics->process_dns_layer(dnsLayer, dir, l3Type, pcpp::TCP, flowKey, port, _static_suffix_size, stamp);
            _static_suffix_size = 0;
        }
        // data is freed upon return
    };

    if (!iter->second.sessionData[side]) {
        iter->second.sessionData[side] = std::make_unique<DnsXactTcpSessionData>(got_dns_message);
    }

    iter->second.sessionData[side]->receive_tcp_data(tcpData.getData(), tcpData.getDataLength());
}

void DnsXactStreamHandler::tcp_connection_start_cb(const pcpp::ConnectionData &connectionData)
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

void DnsXactStreamHandler::tcp_connection_end_cb(const pcpp::ConnectionData &connectionData, [[maybe_unused]] pcpp::TcpReassembly::ConnectionEndReason reason)
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
void DnsXactStreamHandler::set_start_tstamp(timespec stamp)
{
    _metrics->set_start_tstamp(stamp);
}
void DnsXactStreamHandler::set_end_tstamp(timespec stamp)
{
    _metrics->set_end_tstamp(stamp);
}
void DnsXactStreamHandler::info_json(json &j) const
{
    common_info_json(j);
    j[schema_key()]["xact"]["open"] = _metrics->num_open_transactions();
    j[schema_key()]["predicate"]["enabled"] = _using_predicate_signals;
}

inline void DnsXactStreamHandler::_register_predicate_filter(Filters filter, std::string f_key, std::string f_value)
{
    if (!_using_predicate_signals && filter == Filters::OnlyRCode) {
        // all DnsXactStreamHandler race to install this predicate, which is only installed once and called once per udp event
        // it's job is to return the predicate "jump key" to call matching signals
        static thread_local auto udp_rcode_predicate = [](pcpp::Packet &payload, PacketDirection, pcpp::ProtocolType, uint32_t flowkey, timespec stamp) -> std::string {
            pcpp::UdpLayer *udpLayer = payload.getLayerOfType<pcpp::UdpLayer>();
            assert(udpLayer);
            if (flowkey != _cached_dns_layer.flowKey || stamp.tv_sec != _cached_dns_layer.timestamp.tv_sec || stamp.tv_nsec != _cached_dns_layer.timestamp.tv_nsec) {
                _cached_dns_layer.flowKey = flowkey;
                _cached_dns_layer.timestamp = stamp;
                _cached_dns_layer.dnsLayer = std::make_unique<DnsLayer>(udpLayer, &payload);
            }
            auto dnsLayer = _cached_dns_layer.dnsLayer.get();
            // return the 'jump key' for pcap to make O(1) call to appropriate signals
            return "dnsonly_rcode" + std::to_string(dnsLayer->getDnsHeader()->responseCode);
        };

        // if the jump key matches, this callback fires
        auto rcode_signal = [this](pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp) {
            process_udp_packet_cb(payload, dir, l3, flowkey, stamp);
        };
        if (_pcap_proxy) {
            // even though predicate and callback are sent, pcap will only install the first one it sees from dns handler
            // module name is sent to allow disconnect at shutdown time
            _pcap_proxy->register_udp_predicate_signal(schema_key(), name(), f_key, f_value, udp_rcode_predicate, rcode_signal);
            _using_predicate_signals = true;
        }
    }
}
inline bool DnsXactStreamHandler::_filtering(DnsLayer &payload, [[maybe_unused]] PacketDirection dir, uint32_t flowkey, timespec stamp)
{
    bool response = false;
    if (payload.getDnsHeader()->queryOrResponse == QR::response) {
        response = true;
        if (_f_enabled[Filters::ExcludingRCode] && payload.getDnsHeader()->responseCode == _f_rcode) {
            goto will_filter;
        }
        if (_f_enabled[Filters::AnswerCount] && payload.getAnswerCount() != _f_answer_count) {
            goto will_filter;
        }
        if (_f_enabled[Filters::OnlyDNSSECResponse]) {
            if ((payload.getDnsHeader()->queryOrResponse != QR::response) || !payload.getAnswerCount()) {
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
            if (!geo::GeoIP().enabled() || !payload.getAdditionalRecordCount()) {
                goto will_filter;
            }
            if (!payload.parseResources(false, true, true) || payload.getFirstAdditionalRecord() == nullptr) {
                goto will_filter;
            }
            auto ecs = parse_additional_records_ecs(payload.getFirstAdditionalRecord());
            if (!ecs || ecs->client_subnet.empty() || (geo::GeoIP().getGeoLocString(ecs->client_subnet.c_str()) != "Unknown")) {
                goto will_filter;
            }
        }
        if (_f_enabled[Filters::AsnNotFound]) {
            if (!geo::GeoASN().enabled() || !payload.getAdditionalRecordCount()) {
                goto will_filter;
            }
            if (!payload.parseResources(false, true, true) || payload.getFirstAdditionalRecord() == nullptr) {
                goto will_filter;
            }
            auto ecs = parse_additional_records_ecs(payload.getFirstAdditionalRecord());
            if (!ecs || ecs->client_subnet.empty() || (geo::GeoASN().getASNString(ecs->client_subnet.c_str()) != "Unknown")) {
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
    _metrics->process_filtered(stamp, response, flowkey, payload.getDnsHeader()->transactionID);
    return true;
}
inline bool DnsXactStreamHandler::_configs(DnsLayer &payload)
{
    // should only work if OnlyQNameSuffix is not enabled
    if (_c_enabled[Configs::PublicSuffixList] && !_f_enabled[Filters::OnlyQNameSuffix] && payload.parseResources(true) && payload.getFirstQuery() != nullptr) {
        _static_suffix_size = match_public_suffix(payload.getFirstQuery()->getNameLower());
    }

    return true;
}
void DnsXactMetricsBucket::specialized_merge(const AbstractMetricsBucket &o)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const DnsXactMetricsBucket &>(o);

    // rates maintain their own thread safety
    _rate_total.merge(other._rate_total);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    if (group_enabled(group::xact::DnsXactMetrics::DnsTransactions)) {
        _counters.xacts_filtered += other._counters.xacts_filtered;
        _counters.xacts_unknown_dir += other._counters.xacts_unknown_dir;

        _counters.xacts_total += other._counters.xacts_total;
        _counters.xacts_in += other._counters.xacts_in;
        _counters.xacts_out += other._counters.xacts_out;
        _counters.xacts_timed_out += other._counters.xacts_timed_out;

        _dnsXactFromTimeUs.merge(other._dnsXactFromTimeUs);
        _dnsXactToTimeUs.merge(other._dnsXactToTimeUs);
        _dnsXactRatio.merge(other._dnsXactRatio);
        _dns_slowXactIn.merge(other._dns_slowXactIn);
        _dns_slowXactOut.merge(other._dns_slowXactOut);
    }
}

void DnsXactMetricsBucket::to_json(json &j) const
{

    bool live_rates = !read_only() && !recorded_stream();
    _rate_total.to_json(j, live_rates);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_json(j, live_rates);
        num_events->to_json(j);
        num_samples->to_json(j);
    }

    std::shared_lock r_lock(_mutex);

    if (group_enabled(group::xact::DnsXactMetrics::DnsTransactions)) {
        _counters.xacts_filtered.to_json(j);
        _counters.xacts_unknown_dir.to_json(j);

        _counters.xacts_total.to_json(j);
        _counters.xacts_timed_out.to_json(j);

        _counters.xacts_in.to_json(j);
        _dns_slowXactIn.to_json(j);

        _dnsXactFromTimeUs.to_json(j);
        _dnsXactToTimeUs.to_json(j);
        _dnsXactRatio.to_json(j);

        _counters.xacts_out.to_json(j);
        _dns_slowXactOut.to_json(j);
    }
}

void DnsXactMetricsBucket::new_dns_transaction(bool deep, float to90th, float from90th, DnsLayer &dns, PacketDirection dir, DnsTransaction xact)
{

    uint64_t xactTime = ((xact.totalTS.tv_sec * 1'000'000'000L) + xact.totalTS.tv_nsec) / 1'000; // nanoseconds to microseconds

    // lock for write
    std::unique_lock lock(_mutex);
    ++_rate_total;
    ++_counters.xacts_total;

    if (dir == PacketDirection::toHost) {
        ++_counters.xacts_out;
        if (deep) {
            _dnsXactFromTimeUs.update(xactTime);
        }
    } else if (dir == PacketDirection::fromHost) {
        ++_counters.xacts_in;
        if (deep) {
            _dnsXactToTimeUs.update(xactTime);
        }
    } else {
        ++_counters.xacts_unknown_dir;
    }

    if (deep) {
        if (xact.querySize) {
            _dnsXactRatio.update(static_cast<double>(dns.getDataLen()) / xact.querySize);
        }

        auto query = dns.getFirstQuery();
        if (query) {
            auto name = query->getName();
            // dir is the direction of the last packet, meaning the reply so from a transaction perspective
            // we look at it from the direction of the query, so the opposite side than we have here
            if (dir == PacketDirection::toHost && from90th > 0 && xactTime >= from90th) {
                _dns_slowXactOut.update(name);
            } else if (dir == PacketDirection::fromHost && to90th > 0 && xactTime >= to90th) {
                _dns_slowXactIn.update(name);
            }
        }
    }
}
void DnsXactMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{
    _rate_total.to_prometheus(out, add_labels);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_prometheus(out, add_labels);
        num_events->to_prometheus(out, add_labels);
        num_samples->to_prometheus(out, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    if (group_enabled(group::xact::DnsXactMetrics::DnsTransactions)) {
        _counters.xacts_filtered.to_prometheus(out, add_labels);
        _counters.xacts_unknown_dir.to_prometheus(out, add_labels);

        _counters.xacts_total.to_prometheus(out, add_labels);
        _counters.xacts_timed_out.to_prometheus(out, add_labels);

        _counters.xacts_in.to_prometheus(out, add_labels);
        _dns_slowXactIn.to_prometheus(out, add_labels);

        _dnsXactFromTimeUs.to_prometheus(out, add_labels);
        _dnsXactToTimeUs.to_prometheus(out, add_labels);
        _dnsXactRatio.to_prometheus(out, add_labels);

        _counters.xacts_out.to_prometheus(out, add_labels);
        _dns_slowXactOut.to_prometheus(out, add_labels);
    }
}
void DnsXactMetricsBucket::process_filtered()
{
    std::unique_lock lock(_mutex);
    ++_counters.xacts_filtered;
}

// the general metrics manager entry point (both UDP and TCP)
void DnsXactMetricsManager::process_dns_layer(DnsLayer &payload, PacketDirection dir, [[maybe_unused]] pcpp::ProtocolType l3, [[maybe_unused]] pcpp::ProtocolType l4, uint32_t flowkey, [[maybe_unused]] uint16_t port, [[maybe_unused]] size_t suffix_size, timespec stamp)
{
    if (group_enabled(group::xact::DnsXactMetrics::DnsTransactions)) {
        // base event
        new_event(stamp);
        // handle dns transactions (query/response pairs)
        if (payload.getDnsHeader()->queryOrResponse == QR::response) {
            auto xact = _qr_pair_manager.maybe_end_transaction(flowkey, payload.getDnsHeader()->transactionID, stamp);
            if (xact.first) {
                live_bucket()->new_dns_transaction(_deep_sampling_now, _to90th, _from90th, payload, dir, xact.second);
            }
        } else {
            _qr_pair_manager.start_transaction(flowkey, payload.getDnsHeader()->transactionID, stamp, payload.getDataLen());
        }
    }
}
void DnsXactMetricsManager::process_filtered(timespec stamp, bool response, uint32_t flowKey, uint16_t transactionID)
{
    // base event, no sample
    new_event(stamp, false);
    if (response) {
        _qr_pair_manager.maybe_end_transaction(flowKey, transactionID, stamp);
    }
    live_bucket()->process_filtered();
}
void DnsXactMetricsManager::process_dnstap(const dnstap::Dnstap &payload, bool filtered)
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
        side = QR::response;
        break;
    case dnstap::Message_Type_FORWARDER_RESPONSE:
    case dnstap::Message_Type_STUB_RESPONSE:
    case dnstap::Message_Type_TOOL_RESPONSE:
    case dnstap::Message_Type_UPDATE_RESPONSE:
        std::timespec_get(&stamp, TIME_UTC);
        side = QR::response;
        break;
    case dnstap::Message_Type_CLIENT_QUERY:
    case dnstap::Message_Type_AUTH_QUERY:
    case dnstap::Message_Type_RESOLVER_QUERY:
        if (payload.message().has_query_time_sec()) {
            stamp.tv_sec = payload.message().query_time_sec();
            stamp.tv_nsec = payload.message().query_time_nsec();
        }
        side = QR::query;
        break;
    case dnstap::Message_Type_FORWARDER_QUERY:
    case dnstap::Message_Type_STUB_QUERY:
    case dnstap::Message_Type_TOOL_QUERY:
    case dnstap::Message_Type_UPDATE_QUERY:
        std::timespec_get(&stamp, TIME_UTC);
        side = QR::query;
        break;
    default:
        // use now()
        std::timespec_get(&stamp, TIME_UTC);
    }

    if (filtered) {
        return process_filtered(stamp, (side == QR::response), static_cast<uint32_t>(payload.message().query_port() + payload.message().response_port()), 0);
    }
    // base event
    new_event(stamp);
    // process in the "live" bucket. this will parse the resources if we are deep sampling
    if (!payload.message().has_query_message() && !payload.message().has_response_message()) {
        return;
    }

    if (side == QR::query && payload.message().has_query_message()) {
        auto query = payload.message().query_message();
        uint8_t *buf = new uint8_t[query.size()];
        std::memcpy(buf, query.c_str(), query.size());
        // DnsLayer takes ownership of buf
        DnsLayer dpayload(buf, query.size(), nullptr, nullptr);
        _qr_pair_manager.start_transaction(static_cast<uint32_t>(payload.message().query_port() + payload.message().response_port()), dpayload.getDnsHeader()->transactionID, stamp, dpayload.getDataLen());
    } else if (side == QR::response && payload.message().has_response_message()) {
        auto query = payload.message().response_message();
        uint8_t *buf = new uint8_t[query.size()];
        std::memcpy(buf, query.c_str(), query.size());
        // DnsLayer takes ownership of buf
        DnsLayer dpayload(buf, query.size(), nullptr, nullptr);
        auto xact = _qr_pair_manager.maybe_end_transaction(static_cast<uint32_t>(payload.message().query_port() + payload.message().response_port()), dpayload.getDnsHeader()->transactionID, stamp);
        if (xact.first) {
            live_bucket()->new_dns_transaction(_deep_sampling_now, _to90th, _from90th, dpayload, PacketDirection::unknown, xact.second);
        }
    }
}
}
