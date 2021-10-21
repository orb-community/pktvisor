/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "NetStreamHandler.h"
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
#include <arpa/inet.h>
#include <cpc_union.hpp>
#include <fmt/format.h>

namespace visor::handler::net {

NetStreamHandler::NetStreamHandler(const std::string &name, InputStream *stream, const Configurable *window_config)
    : visor::StreamMetricsHandler<NetworkMetricsManager>(name, window_config)
{
    assert(stream);
    // figure out which input stream we have
    _pcap_stream = dynamic_cast<PcapInputStream *>(stream);
    _mock_stream = dynamic_cast<MockInputStream *>(stream);
    if (!_pcap_stream && !_mock_stream) {
        throw StreamHandlerException(fmt::format("NetStreamHandler: unsupported input stream {}", stream->name()));
    }
}

void NetStreamHandler::start()
{
    if (_running) {
        return;
    }

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    if (_pcap_stream) {
        _pkt_connection = _pcap_stream->packet_signal.connect(&NetStreamHandler::process_packet_cb, this);
        _start_tstamp_connection = _pcap_stream->start_tstamp_signal.connect(&NetStreamHandler::set_start_tstamp, this);
        _end_tstamp_connection = _pcap_stream->end_tstamp_signal.connect(&NetStreamHandler::set_end_tstamp, this);
    }

    _running = true;
}

void NetStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    if (_pcap_stream) {
        _pkt_connection.disconnect();
        _start_tstamp_connection.disconnect();
        _end_tstamp_connection.disconnect();
    }

    _running = false;
}

NetStreamHandler::~NetStreamHandler()
{
}

// callback from input module
void NetStreamHandler::process_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp)
{
    _metrics->process_packet(payload, dir, l3, l4, stamp);
}
void NetStreamHandler::set_start_tstamp(timespec stamp)
{
    _metrics->set_start_tstamp(stamp);
}
void NetStreamHandler::set_end_tstamp(timespec stamp)
{
    _metrics->set_end_tstamp(stamp);
}

void NetworkMetricsBucket::specialized_merge(const AbstractMetricsBucket &o)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const NetworkMetricsBucket &>(o);

    // rates maintain their own thread safety
    _rate_in.merge(other._rate_in);
    _rate_out.merge(other._rate_out);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _counters.UDP += other._counters.UDP;
    _counters.TCP += other._counters.TCP;
    _counters.OtherL4 += other._counters.OtherL4;
    _counters.IPv4 += other._counters.IPv4;
    _counters.IPv6 += other._counters.IPv6;
    _counters.total_in += other._counters.total_in;
    _counters.total_out += other._counters.total_out;

    _srcIPCard.merge(other._srcIPCard);
    _dstIPCard.merge(other._dstIPCard);

    _topIPv4.merge(other._topIPv4);
    _topIPv6.merge(other._topIPv6);
    _topGeoLoc.merge(other._topGeoLoc);
    _topASN.merge(other._topASN);
}

void NetworkMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{

    _rate_in.to_prometheus(out, add_labels);
    _rate_out.to_prometheus(out, add_labels);

    auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

    event_rate->to_prometheus(out, add_labels);
    num_events->to_prometheus(out, add_labels);
    num_samples->to_prometheus(out, add_labels);
    event_lock.unlock();

    std::shared_lock r_lock(_mutex);

    _counters.UDP.to_prometheus(out, add_labels);
    _counters.TCP.to_prometheus(out, add_labels);
    _counters.OtherL4.to_prometheus(out, add_labels);
    _counters.IPv4.to_prometheus(out, add_labels);
    _counters.IPv6.to_prometheus(out, add_labels);
    _counters.total_in.to_prometheus(out, add_labels);
    _counters.total_out.to_prometheus(out, add_labels);

    _srcIPCard.to_prometheus(out, add_labels);
    _dstIPCard.to_prometheus(out, add_labels);

    _topIPv4.to_prometheus(out, add_labels, [](const uint32_t &val) { return pcpp::IPv4Address(val).toString(); });
    _topIPv6.to_prometheus(out, add_labels);
    _topGeoLoc.to_prometheus(out, add_labels);
    _topASN.to_prometheus(out, add_labels);
}

void NetworkMetricsBucket::to_json(json &j) const
{

    // do rates first, which handle their own locking
    bool live_rates = !read_only() && !recorded_stream();
    _rate_in.to_json(j, live_rates);
    _rate_out.to_json(j, live_rates);

    auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

    event_rate->to_json(j, live_rates);
    num_events->to_json(j);
    num_samples->to_json(j);
    event_lock.unlock();

    std::shared_lock r_lock(_mutex);

    _counters.UDP.to_json(j);
    _counters.TCP.to_json(j);
    _counters.OtherL4.to_json(j);
    _counters.IPv4.to_json(j);
    _counters.IPv6.to_json(j);
    _counters.total_in.to_json(j);
    _counters.total_out.to_json(j);

    _srcIPCard.to_json(j);
    _dstIPCard.to_json(j);

    _topIPv4.to_json(j, [](const uint32_t &val) { return pcpp::IPv4Address(val).toString(); });
    _topIPv6.to_json(j);
    _topGeoLoc.to_json(j);
    _topASN.to_json(j);
}

// the main bucket analysis
void NetworkMetricsBucket::process_packet(bool deep, pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4)
{

    std::unique_lock lock(_mutex);

    switch (dir) {
    case PacketDirection::fromHost:
        ++_counters.total_out;
        ++_rate_out;
        break;
    case PacketDirection::toHost:
        ++_counters.total_in;
        ++_rate_in;
        break;
    case PacketDirection::unknown:
        break;
    }

    switch (l3) {
    case pcpp::IPv6:
        ++_counters.IPv6;
        break;
    case pcpp::IPv4:
        ++_counters.IPv4;
        break;
    default:
        break;
    }

    switch (l4) {
    case pcpp::UDP:
        ++_counters.UDP;
        break;
    case pcpp::TCP:
        ++_counters.TCP;
        break;
    default:
        ++_counters.OtherL4;
        break;
    }

    if (!deep) {
        return;
    }

    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;

    auto IP4layer = payload.getLayerOfType<pcpp::IPv4Layer>();
    auto IP6layer = payload.getLayerOfType<pcpp::IPv6Layer>();
    if (IP4layer) {
        if (dir == PacketDirection::toHost) {
            _srcIPCard.update(IP4layer->getSrcIPv4Address().toInt());
            _topIPv4.update(IP4layer->getSrcIPv4Address().toInt());
            if (geo::enabled()) {
                if (IPv4tosockaddr(IP4layer->getSrcIPv4Address(), &sa4)) {
                    if (geo::GeoIP().enabled()) {
                        _topGeoLoc.update(geo::GeoIP().getGeoLocString(reinterpret_cast<struct sockaddr *>(&sa4)));
                    }
                    if (geo::GeoASN().enabled()) {
                        _topASN.update(geo::GeoASN().getASNString(reinterpret_cast<struct sockaddr *>(&sa4)));
                    }
                }
            }
        } else if (dir == PacketDirection::fromHost) {
            _dstIPCard.update(IP4layer->getDstIPv4Address().toInt());
            _topIPv4.update(IP4layer->getDstIPv4Address().toInt());
            if (geo::enabled()) {
                if (IPv4tosockaddr(IP4layer->getDstIPv4Address(), &sa4)) {
                    if (geo::GeoIP().enabled()) {
                        _topGeoLoc.update(geo::GeoIP().getGeoLocString(reinterpret_cast<struct sockaddr *>(&sa4)));
                    }
                    if (geo::GeoASN().enabled()) {
                        _topASN.update(geo::GeoASN().getASNString(reinterpret_cast<struct sockaddr *>(&sa4)));
                    }
                }
            }
        }
    } else if (IP6layer) {
        if (dir == PacketDirection::toHost) {
            _srcIPCard.update(reinterpret_cast<const void *>(IP6layer->getSrcIPv6Address().toBytes()), 16);
            _topIPv6.update(IP6layer->getSrcIPv6Address().toString());
            if (geo::enabled()) {
                if (IPv6tosockaddr(IP6layer->getSrcIPv6Address(), &sa6)) {
                    if (geo::GeoIP().enabled()) {
                        _topGeoLoc.update(geo::GeoIP().getGeoLocString(reinterpret_cast<struct sockaddr *>(&sa6)));
                    }
                    if (geo::GeoASN().enabled()) {
                        _topASN.update(geo::GeoASN().getASNString(reinterpret_cast<struct sockaddr *>(&sa6)));
                    }
                }
            }
        } else if (dir == PacketDirection::fromHost) {
            _dstIPCard.update(reinterpret_cast<const void *>(IP6layer->getDstIPv6Address().toBytes()), 16);
            _topIPv6.update(IP6layer->getDstIPv6Address().toString());
            if (geo::enabled()) {
                if (IPv6tosockaddr(IP6layer->getDstIPv6Address(), &sa6)) {
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
}

// the general metrics manager entry point
void NetworkMetricsManager::process_packet(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp)
{
    // base event
    new_event(stamp);
    // process in the "live" bucket
    live_bucket()->process_packet(_deep_sampling_now, payload, dir, l3, l4);
}

}