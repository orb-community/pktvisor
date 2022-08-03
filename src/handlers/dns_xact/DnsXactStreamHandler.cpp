/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DnsXactStreamHandler.h"
#include "DnstapInputStream.h"
#include "PublicSuffixList.h"
#include "dns.h"
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
#include <arpa/inet.h>
#include <sstream>
namespace visor::handler::dnsxact {

thread_local DnsXactStreamHandler::DnsCacheData DnsXactStreamHandler::_cached_dns_layer;

DnsXactStreamHandler::DnsXactStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config, StreamHandler *handler)
    : visor::StreamMetricsHandler<DnsXactMetricsManager>(name, window_config)
{
    if (handler) {
        throw StreamHandlerException(fmt::format("DnsXactStreamHandler: unsupported upstream chained stream handler {}", handler->name()));
    }

    assert(proxy);
    // figure out which input event proxy we have
    _pcap_proxy = dynamic_cast<PcapInputEventProxy *>(proxy);
    _dnstap_proxy = dynamic_cast<DnstapInputEventProxy *>(proxy);
    if (!_pcap_proxy && !_dnstap_proxy) {
        throw StreamHandlerException(fmt::format("DnsXactStreamHandler: unsupported input event proxy {}", proxy->name()));
    }
}

void DnsXactStreamHandler::start()
{
    if (_running) {
        return;
    }

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
    }
    if (config_exists("only_dnssec_response")) {
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

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    if (_pcap_proxy) {
        _pkt_udp_connection = _pcap_proxy->udp_signal.connect(&DnsXactStreamHandler::process_udp_packet_cb, this);
        _start_tstamp_connection = _pcap_proxy->start_tstamp_signal.connect(&DnsXactStreamHandler::set_start_tstamp, this);
        _end_tstamp_connection = _pcap_proxy->end_tstamp_signal.connect(&DnsXactStreamHandler::set_end_tstamp, this);
        _tcp_start_connection = _pcap_proxy->tcp_connection_start_signal.connect(&DnsXactStreamHandler::tcp_connection_start_cb, this);
        _tcp_end_connection = _pcap_proxy->tcp_connection_end_signal.connect(&DnsXactStreamHandler::tcp_connection_end_cb, this);
        _tcp_message_connection = _pcap_proxy->tcp_message_ready_signal.connect(&DnsXactStreamHandler::tcp_message_ready_cb, this);
        _heartbeat_connection = _pcap_proxy->heartbeat_signal.connect(&DnsXactStreamHandler::check_period_shift, this);
    } else if (_dnstap_proxy) {
        _dnstap_connection = _dnstap_proxy->dnstap_signal.connect(&DnsXactStreamHandler::process_dnstap_cb, this);
        _heartbeat_connection = _dnstap_proxy->heartbeat_signal.connect(&DnsXactStreamHandler::check_period_shift, this);
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
        if (!_filtering(*dnsLayer, dir, l3, pcpp::UDP, metric_port, stamp)) {
            _metrics->process_dns_layer(*dnsLayer, dir, flowkey, stamp);
        }
    }
}

void TcpSessionData::receive_dns_wire_data(const uint8_t *data, size_t len)
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
            auto data = std::make_unique<uint8_t[]>(size);
            std::memcpy(data.get(), _buffer.data() + sizeof(size), size);
            _buffer.erase(0, sizeof(size) + size);
            _got_dns_msg(std::move(data), size);
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
        if (!_filtering(dnsLayer, dir, l3Type, pcpp::UDP, port, stamp)) {
            _metrics->process_dns_layer(dnsLayer, dir, flowKey, stamp);
        }
        // data is freed upon return
    };

    if (!iter->second.sessionData[side]) {
        iter->second.sessionData[side] = std::make_unique<TcpSessionData>(got_dns_message);
    }

    iter->second.sessionData[side]->receive_dns_wire_data(tcpData.getData(), tcpData.getDataLength());
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
}

inline bool DnsXactStreamHandler::_filtering(DnsLayer &payload, [[maybe_unused]] PacketDirection dir, [[maybe_unused]] pcpp::ProtocolType l3, [[maybe_unused]] pcpp::ProtocolType l4, [[maybe_unused]] uint16_t port, timespec stamp)
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
            if (!payload.getAnswerCount() || !payload.parseResources(false, true, true) || payload.getFirstAnswer() == nullptr) {
                goto will_filter;
            }
            bool has_ssig{false};
            auto dns_answer = payload.getFirstAnswer();
            for (size_t i = 0; i < payload.getAnswerCount(); ++i) {
                if (!dns_answer) {
                    break;
                }
                if (dns_answer->getDnsType() == pcpp::DNS_TYPE_RRSIG) {
                    has_ssig = true;
                    break;
                }
                dns_answer = payload.getNextAnswer(dns_answer);
            }
            if (!has_ssig) {
                goto will_filter;
            }
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
    if (_f_enabled[Filters::OnlyQNameSuffix]) {
        if (!payload.parseResources(true) || payload.getFirstQuery() == nullptr) {
            goto will_filter;
        }
        std::string_view qname_ci = payload.getFirstQuery()->getNameLower();
        if (std::none_of(_f_qnames.begin(), _f_qnames.end(), [this, qname_ci](std::string fqn) {
                return ends_with(qname_ci, fqn);
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

void DnsXactMetricsBucket::specialized_merge(const AbstractMetricsBucket &o)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const DnsXactMetricsBucket &>(o);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _counters.filtered += other._counters.filtered;

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

void DnsXactMetricsBucket::to_json(json &j) const
{

    bool live_rates = !read_only() && !recorded_stream();

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_json(j, live_rates);
        num_events->to_json(j);
        num_samples->to_json(j);
    }

    std::shared_lock r_lock(_mutex);

    _counters.filtered.to_json(j);

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

// the main bucket analysis
void DnsXactMetricsBucket::process_dnstap(bool deep, const dnstap::Dnstap &payload)
{
    std::unique_lock lock(_mutex);
}

void DnsXactMetricsBucket::new_dns_transaction(bool deep, float to90th, float from90th, DnsLayer &dns, PacketDirection dir, DnsTransaction xact)
{

    uint64_t xactTime = ((xact.totalTS.tv_sec * 1'000'000'000L) + xact.totalTS.tv_nsec) / 1'000; // nanoseconds to microseconds

    // lock for write
    std::unique_lock lock(_mutex);

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

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_prometheus(out, add_labels);
        num_events->to_prometheus(out, add_labels);
        num_samples->to_prometheus(out, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    _counters.filtered.to_prometheus(out, add_labels);

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
void DnsXactMetricsBucket::process_filtered()
{
    std::unique_lock lock(_mutex);
    ++_counters.filtered;
}

// the general metrics manager entry point (both UDP and TCP)
void DnsXactMetricsManager::process_dns_layer(DnsLayer &payload, PacketDirection dir, uint32_t flowkey, timespec stamp)
{
    // base event
    new_event(stamp);
    // handle dns transactions (query/response pairs)
    if (payload.getDnsHeader()->queryOrResponse == QRXact::response) {
        auto xact = _qr_pair_manager.maybe_end_transaction(flowkey, payload.getDnsHeader()->transactionID, stamp);
        if (xact.first) {
            live_bucket()->new_dns_transaction(_deep_sampling_now, _to90th, _from90th, payload, dir, xact.second);
        }
    } else {
        _qr_pair_manager.start_transaction(flowkey, payload.getDnsHeader()->transactionID, stamp, payload.getDataLen());
    }
}
void DnsXactMetricsManager::process_filtered(timespec stamp)
{
    // base event, no sample
    new_event(stamp, false);
    live_bucket()->process_filtered();
}
void DnsXactMetricsManager::process_dnstap(const dnstap::Dnstap &payload, bool filtered)
{
    // dnstap message type
    auto mtype = payload.message().type();
    // set proper timestamp. use dnstap version if available, otherwise "now"
    timespec stamp;
    switch (mtype) {
    case dnstap::Message_Type_CLIENT_RESPONSE:
    case dnstap::Message_Type_AUTH_RESPONSE:
    case dnstap::Message_Type_RESOLVER_RESPONSE:
        if (payload.message().has_response_time_sec()) {
            stamp.tv_sec = payload.message().response_time_sec();
            stamp.tv_nsec = payload.message().response_time_nsec();
        }
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
    // base event
    new_event(stamp);
    // process in the "live" bucket. this will parse the resources if we are deep sampling
    live_bucket()->process_dnstap(_deep_sampling_now, payload);
}
}
