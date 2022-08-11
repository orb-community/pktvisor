/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DhcpStreamHandler.h"

namespace visor::handler::dhcp {

DhcpStreamHandler::DhcpStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config, StreamHandler *handler)
    : visor::StreamMetricsHandler<DhcpMetricsManager>(name, window_config)
{
    if (handler) {
        throw StreamHandlerException(fmt::format("DhcpStreamHandler: unsupported upstream chained stream handler {}", handler->name()));
    }

    assert(proxy);
    // figure out which input event proxy we have
    _pcap_proxy = dynamic_cast<PcapInputEventProxy *>(proxy);
    if (!_pcap_proxy) {
        throw StreamHandlerException(fmt::format("DhcpStreamHandler: unsupported input event proxy {}", proxy->name()));
    }
}

// callback from input module
void DhcpStreamHandler::process_udp_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp)
{
    pcpp::UdpLayer *udpLayer = payload.getLayerOfType<pcpp::UdpLayer>();
    assert(udpLayer);

    auto dst_port = ntohs(udpLayer->getUdpHeader()->portDst);
    auto src_port = ntohs(udpLayer->getUdpHeader()->portSrc);
    if (dst_port == 67 || src_port == 67 || dst_port == 68 || src_port == 68) {
        pcpp::DhcpLayer dhcpLayer(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize(), udpLayer, &payload);
        if (!_filtering(&dhcpLayer, dir, l3, pcpp::UDP, src_port, dst_port, stamp)) {
            _metrics->process_dhcp_layer(&dhcpLayer, dir, l3, pcpp::UDP, flowkey, src_port, dst_port, stamp);
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

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _counters.DISCOVER += other._counters.DISCOVER;
    _counters.OFFER += other._counters.OFFER;
    _counters.REQUEST += other._counters.REQUEST;
    _counters.ACK += other._counters.ACK;
    _counters.total += other._counters.total;
    _counters.filtered += other._counters.filtered;
}

void DhcpMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{

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
}

void DhcpMetricsBucket::to_json(json &j) const
{

    bool live_rates = !read_only() && !recorded_stream();

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
}

void DhcpMetricsBucket::process_filtered()
{
    std::unique_lock lock(_mutex);
    ++_counters.filtered;
}

bool DhcpStreamHandler::_filtering(pcpp::DhcpLayer *payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint16_t src_port, uint16_t dst_port, timespec stamp)
{
    // no filters yet
    return false;
}

void DhcpMetricsBucket::process_dhcp_layer(bool deep, pcpp::DhcpLayer *payload, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint16_t src_port, uint16_t dst_port)
{
    std::unique_lock lock(_mutex);

    ++_counters.total;

    switch (payload->getMesageType()) {
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
    }
}

void DhcpMetricsManager::process_dhcp_layer(pcpp::DhcpLayer *payload, [[maybe_unused]] PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, [[maybe_unused]] uint32_t flowkey, uint16_t src_port, uint16_t dst_port, timespec stamp)
{
    // base event
    new_event(stamp);
    // process in the "live" bucket. this will parse the resources if we are deep sampling
    live_bucket()->process_dhcp_layer(_deep_sampling_now, payload, l3, l4, src_port, dst_port);
}

void DhcpMetricsManager::process_filtered(timespec stamp)
{
    // base event, no sample
    new_event(stamp, false);
    live_bucket()->process_filtered();
}

}