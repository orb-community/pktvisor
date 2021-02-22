#include "NetStreamHandler.h"
#include "GeoDB.h"
#include "utils.h"
#include <Corrade/Utility/Debug.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#pragma GCC diagnostic pop
#include <arpa/inet.h>
#include <cpc_union.hpp>

namespace vizer::handler::net {

NetStreamHandler::NetStreamHandler(const std::string &name, PcapInputStream *stream, uint periods, uint deepSampleRate)
    : vizer::StreamMetricsHandler<NetworkMetricsManager>(name, periods, deepSampleRate)
    , _stream(stream)
{
    assert(stream);
}

void NetStreamHandler::start()
{
    if (_running) {
        return;
    }

    _pkt_connection = _stream->packet_signal.connect(&NetStreamHandler::process_packet_cb, this);
    _start_tstamp_connection = _stream->start_tstamp_signal.connect(&NetStreamHandler::set_initial_tstamp, this);

    _running = true;
}

void NetStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    _pkt_connection.disconnect();
    _start_tstamp_connection.disconnect();

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

void NetStreamHandler::to_json(json &j, uint64_t period, bool merged)
{
    if (merged) {
        _metrics->to_json_merged(j, "packets", period);
    } else {
        _metrics->to_json_single(j, "packets", period);
    }
}
void NetStreamHandler::set_initial_tstamp(timespec stamp)
{
    _metrics->set_initial_tstamp(stamp);
}
json NetStreamHandler::info_json() const
{
    json result;
    result["periods"] = _metrics->num_periods();
    result["current_periods"] = _metrics->current_periods();
    result["deep_sample_rate"] = _metrics->deep_sample_rate();
    std::stringstream ss;
    auto in_time_t = std::chrono::system_clock::to_time_t(_metrics->start_time());
    ss << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%d %X");
    result["start_time"] = ss.str();
    return result;
}

void NetworkMetricsBucket::specialized_merge(const AbstractMetricsBucket &o)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const NetworkMetricsBucket &>(o);

    // rates maintain their own thread safety
    _rate_in.merge(other._rate_in);
    _rate_out.merge(other._rate_out);
    _rate_total.merge(other._rate_total);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _counters.UDP += other._counters.UDP;
    _counters.TCP += other._counters.TCP;
    _counters.OtherL4 += other._counters.OtherL4;
    _counters.IPv6 += other._counters.IPv6;
    _counters.total_in += other._counters.total_in;
    _counters.total_out += other._counters.total_out;

    datasketches::cpc_union merge_srcIPCard;
    merge_srcIPCard.update(_srcIPCard);
    merge_srcIPCard.update(other._srcIPCard);
    _srcIPCard = merge_srcIPCard.get_result();

    datasketches::cpc_union merge_dstIPCard;
    merge_dstIPCard.update(_dstIPCard);
    merge_dstIPCard.update(other._dstIPCard);
    _dstIPCard = merge_dstIPCard.get_result();

    _topIPv4.merge(other._topIPv4);
    _topIPv6.merge(other._topIPv6);
    _topGeoLoc.merge(other._topGeoLoc);
    _topASN.merge(other._topASN);
}

void NetworkMetricsBucket::to_json(json &j) const
{

    const double fractions[4]{0.50, 0.90, 0.95, 0.99};

    // do rates first, which handle their own locking
    {
        auto [rate_quantile, rate_lock] = _rate_in.quantile_get_rlocked();
        auto quantiles = rate_quantile->get_quantiles(fractions, 4);
        if (quantiles.size()) {
            j["rates"]["pps_in"]["p50"] = quantiles[0];
            j["rates"]["pps_in"]["p90"] = quantiles[1];
            j["rates"]["pps_in"]["p95"] = quantiles[2];
            j["rates"]["pps_in"]["p99"] = quantiles[3];
        }
    }

    {
        auto [rate_quantile, rate_lock] = _rate_out.quantile_get_rlocked();
        auto quantiles = rate_quantile->get_quantiles(fractions, 4);
        if (quantiles.size()) {
            j["rates"]["pps_out"]["p50"] = quantiles[0];
            j["rates"]["pps_out"]["p90"] = quantiles[1];
            j["rates"]["pps_out"]["p95"] = quantiles[2];
            j["rates"]["pps_out"]["p99"] = quantiles[3];
        }
    }

    {
        auto [rate_quantile, rate_lock] = _rate_total.quantile_get_rlocked();
        auto quantiles = rate_quantile->get_quantiles(fractions, 4);
        if (quantiles.size()) {
            j["rates"]["pps_total"]["p50"] = quantiles[0];
            j["rates"]["pps_total"]["p90"] = quantiles[1];
            j["rates"]["pps_total"]["p95"] = quantiles[2];
            j["rates"]["pps_total"]["p99"] = quantiles[3];
        }
    }

    auto [num_events, num_samples] = event_data(); // thread safe
    std::shared_lock r_lock(_mutex);

    j["total"] = num_events;
    j["samples"] = num_samples;
    j["udp"] = _counters.UDP;
    j["tcp"] = _counters.TCP;
    j["other_l4"] = _counters.OtherL4;
    j["ipv4"] = _counters.IPv4;
    j["ipv6"] = _counters.IPv6;
    j["in"] = _counters.total_in;
    j["out"] = _counters.total_out;

    j["cardinality"]["src_ips_in"] = lround(_srcIPCard.get_estimate());
    j["cardinality"]["dst_ips_out"] = lround(_dstIPCard.get_estimate());

    {
        j["top_ipv4"] = nlohmann::json::array();
        auto items = _topIPv4.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j["top_ipv4"][i]["name"] = pcpp::IPv4Address(items[i].get_item()).toString();
            j["top_ipv4"][i]["estimate"] = items[i].get_estimate();
        }
    }

    {
        j["top_ipv6"] = nlohmann::json::array();
        auto items = _topIPv6.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j["top_ipv6"][i]["name"] = items[i].get_item();
            j["top_ipv6"][i]["estimate"] = items[i].get_estimate();
        }
    }

    {
        j["top_geoLoc"] = nlohmann::json::array();
        auto items = _topGeoLoc.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j["top_geoLoc"][i]["name"] = items[i].get_item();
            j["top_geoLoc"][i]["estimate"] = items[i].get_estimate();
        }
    }

    {
        j["top_ASN"] = nlohmann::json::array();
        auto items = _topASN.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j["top_ASN"][i]["name"] = items[i].get_item();
            j["top_ASN"][i]["estimate"] = items[i].get_estimate();
        }
    }
}

// the main bucket analysis
void NetworkMetricsBucket::process_packet(bool deep, pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp)
{

    ++_rate_total;

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
            _srcIPCard.update(IP4layer->getSrcIpAddress().toInt());
            _topIPv4.update(IP4layer->getSrcIpAddress().toInt());
            if (geo::enabled()) {
                if (IPv4tosockaddr(IP4layer->getSrcIpAddress(), &sa4)) {
                    if (geo::GeoIP().enabled()) {
                        _topGeoLoc.update(geo::GeoIP().getGeoLocString((struct sockaddr *)&sa4));
                    }
                    if (geo::GeoASN().enabled()) {
                        _topASN.update(geo::GeoASN().getASNString((struct sockaddr *)&sa4));
                    }
                }
            }
        } else if (dir == PacketDirection::fromHost) {
            _dstIPCard.update(IP4layer->getDstIpAddress().toInt());
            _topIPv4.update(IP4layer->getDstIpAddress().toInt());
            if (geo::enabled()) {
                if (IPv4tosockaddr(IP4layer->getDstIpAddress(), &sa4)) {
                    if (geo::GeoIP().enabled()) {
                        _topGeoLoc.update(geo::GeoIP().getGeoLocString((struct sockaddr *)&sa4));
                    }
                    if (geo::GeoASN().enabled()) {
                        _topASN.update(geo::GeoASN().getASNString((struct sockaddr *)&sa4));
                    }
                }
            }
        }
    } else if (IP6layer) {
        if (dir == PacketDirection::toHost) {
            _srcIPCard.update((void *)IP6layer->getSrcIpAddress().toBytes(), 16);
            _topIPv6.update(IP6layer->getSrcIpAddress().toString());
            if (geo::enabled()) {
                if (IPv6tosockaddr(IP6layer->getSrcIpAddress(), &sa6)) {
                    if (geo::GeoIP().enabled()) {
                        _topGeoLoc.update(geo::GeoIP().getGeoLocString((struct sockaddr *)&sa6));
                    }
                    if (geo::GeoASN().enabled()) {
                        _topASN.update(geo::GeoASN().getASNString((struct sockaddr *)&sa6));
                    }
                }
            }
        } else if (dir == PacketDirection::fromHost) {
            _dstIPCard.update((void *)IP6layer->getDstIpAddress().toBytes(), 16);
            _topIPv6.update(IP6layer->getDstIpAddress().toString());
            if (geo::enabled()) {
                if (IPv6tosockaddr(IP6layer->getDstIpAddress(), &sa6)) {
                    if (geo::GeoIP().enabled()) {
                        _topGeoLoc.update(geo::GeoIP().getGeoLocString((struct sockaddr *)&sa6));
                    }
                    if (geo::GeoASN().enabled()) {
                        _topASN.update(geo::GeoASN().getASNString((struct sockaddr *)&sa6));
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
    _metric_buckets.back()->process_packet(_deep_sampling_now, payload, dir, l3, l4, stamp);
}

}