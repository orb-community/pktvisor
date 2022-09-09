/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DhcpStreamHandler.h"

namespace visor::handler::dhcp {

DhcpStreamHandler::DhcpStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config)
    : visor::StreamMetricsHandler<DhcpMetricsManager>(name, window_config)
{
    assert(proxy);
    // figure out which input event proxy we have
    _pcap_proxy = dynamic_cast<PcapInputEventProxy *>(proxy);
    if (!_pcap_proxy) {
        throw StreamHandlerException(fmt::format("DhcpStreamHandler: unsupported input event proxy {}", proxy->name()));
    }
}

// callback from input module
void DhcpStreamHandler::process_udp_packet_cb(pcpp::Packet &payload, PacketDirection dir, [[maybe_unused]] pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp)
{
    pcpp::UdpLayer *udpLayer = payload.getLayerOfType<pcpp::UdpLayer>();
    assert(udpLayer);

    auto dst_port = ntohs(udpLayer->getUdpHeader()->portDst);
    auto src_port = ntohs(udpLayer->getUdpHeader()->portSrc);
    if (dst_port == 67 || src_port == 67 || dst_port == 68 || src_port == 68) {
        pcpp::DhcpLayer dhcpLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize(), udpLayer, &payload);
        if (!_filtering(&dhcpLayer, dir, stamp)) {
            _metrics->process_dhcp_layer(&dhcpLayer, dir, flowkey, stamp);
        }
    }
}

void DhcpStreamHandler::start()
{
    if (_running) {
        return;
    }

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    if (_pcap_proxy) {
        _pkt_udp_connection = _pcap_proxy->udp_signal.connect(&DhcpStreamHandler::process_udp_packet_cb, this);
        _start_tstamp_connection = _pcap_proxy->start_tstamp_signal.connect(&DhcpStreamHandler::set_start_tstamp, this);
        _end_tstamp_connection = _pcap_proxy->end_tstamp_signal.connect(&DhcpStreamHandler::set_end_tstamp, this);
        _heartbeat_connection = _pcap_proxy->heartbeat_signal.connect(&DhcpStreamHandler::check_period_shift, this);
    }

    _running = true;
}

void DhcpStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    if (_pcap_proxy) {
        _pkt_udp_connection.disconnect();
        _start_tstamp_connection.disconnect();
        _end_tstamp_connection.disconnect();
        _heartbeat_connection.disconnect();
    }

    _running = false;
}

// callback from input module
void DhcpStreamHandler::set_start_tstamp(timespec stamp)
{
    _metrics->set_start_tstamp(stamp);
}
void DhcpStreamHandler::set_end_tstamp(timespec stamp)
{
    _metrics->set_end_tstamp(stamp);
}

void DhcpMetricsBucket::specialized_merge(const AbstractMetricsBucket &o)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const DhcpMetricsBucket &>(o);

    // rates maintain their own thread safety
    _rate_total.merge(other._rate_total);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _counters.DISCOVER += other._counters.DISCOVER;
    _counters.OFFER += other._counters.OFFER;
    _counters.REQUEST += other._counters.REQUEST;
    _counters.ACK += other._counters.ACK;
    _counters.total += other._counters.total;
    _counters.filtered += other._counters.filtered;

    _dhcp_clients.merge(other._dhcp_clients);
}

void DhcpMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{

    _rate_total.to_prometheus(out, add_labels);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_prometheus(out, add_labels);
        num_events->to_prometheus(out, add_labels);
        num_samples->to_prometheus(out, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    _counters.DISCOVER.to_prometheus(out, add_labels);
    _counters.OFFER.to_prometheus(out, add_labels);
    _counters.REQUEST.to_prometheus(out, add_labels);
    _counters.ACK.to_prometheus(out, add_labels);
    _counters.total.to_prometheus(out, add_labels);
    _counters.filtered.to_prometheus(out, add_labels);

    _dhcp_clients.to_prometheus(out, add_labels);
}

void DhcpMetricsBucket::to_json(json &j) const
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

    _counters.DISCOVER.to_json(j);
    _counters.OFFER.to_json(j);
    _counters.REQUEST.to_json(j);
    _counters.ACK.to_json(j);
    _counters.total.to_json(j);
    _counters.filtered.to_json(j);

    _dhcp_clients.to_json(j);
}

void DhcpMetricsBucket::process_filtered()
{
    std::unique_lock lock(_mutex);
    ++_counters.filtered;
}

bool DhcpStreamHandler::_filtering([[maybe_unused]] pcpp::DhcpLayer *payload, [[maybe_unused]] PacketDirection dir, [[maybe_unused]] timespec stamp)
{
    // no filters yet
    return false;
}

void DhcpMetricsBucket::process_dhcp_layer([[maybe_unused]] bool deep, pcpp::DhcpLayer *payload)
{
    std::unique_lock lock(_mutex);

    ++_counters.total;
    ++_rate_total;

    switch (payload->getMessageType()) {
    case pcpp::DHCP_DISCOVER:
        ++_counters.DISCOVER;
        break;
    case pcpp::DHCP_OFFER:
        ++_counters.OFFER;
        break;
    case pcpp::DHCP_REQUEST:
        ++_counters.REQUEST;
        break;
    case pcpp::DHCP_ACK:
        ++_counters.ACK;
        break;
    default:
        break;
    }
}
void DhcpMetricsBucket::new_dhcp_transaction(bool deep, pcpp::DhcpLayer *payload, DhcpTransaction &xact)
{
    if (!deep) {
        return;
    }
    // lock for write
    std::unique_lock lock(_mutex);

    if (auto client_ip = payload->getYourIpAddress(); client_ip.isValid()) {
        _dhcp_clients.update(client_ip.toString() + "/" + xact.mac_address + "/" + xact.hostname);
    }
}

void DhcpMetricsManager::process_dhcp_layer(pcpp::DhcpLayer *payload, [[maybe_unused]] PacketDirection dir, [[maybe_unused]] uint32_t flowkey, timespec stamp)
{
    // base event
    new_event(stamp);
    // process in the "live" bucket. this will parse the resources if we are deep sampling
    live_bucket()->process_dhcp_layer(_deep_sampling_now, payload);

    auto type = payload->getMessageType();
    if (type == pcpp::DHCP_REQUEST) {
        std::string hostname;
        if (auto option = payload->getOptionData(pcpp::DhcpOptionTypes::DHCPOPT_HOST_NAME); option.isNull() != true) {
            hostname = option.getValueAsString();
        }
        auto mac_address = payload->getClientHardwareAddress().toString();
        _request_ack_manager.start_transaction(payload->getDhcpHeader()->transactionID, stamp, hostname, mac_address);
    } else if (type == pcpp::DHCP_ACK) {
        auto xact = _request_ack_manager.maybe_end_transaction(payload->getDhcpHeader()->transactionID);
        if (xact.first) {
            live_bucket()->new_dhcp_transaction(_deep_sampling_now, payload, xact.second);
        }
    }
}

void DhcpMetricsManager::process_filtered(timespec stamp)
{
    // base event, no sample
    new_event(stamp, false);
    live_bucket()->process_filtered();
}

}