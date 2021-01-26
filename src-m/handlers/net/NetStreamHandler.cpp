#include "NetStreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <datasketches/datasketches/cpc/cpc_union.hpp>

namespace pktvisor::handler {

NetStreamHandler::NetStreamHandler(const std::string &name, PcapInputStream *stream)
    : pktvisor::StreamHandler(name)
    , _stream(stream)
    // TODO
    , _metrics(false, 5, 100)
{
    !Corrade::Utility::Debug{} << "create";
}

void NetStreamHandler::start()
{
    if (_running) {
        return;
    }

    _running = true;
    !Corrade::Utility::Debug{} << "start";

    _pkt_connection = _stream->packet_signal.connect(&NetStreamHandler::process_packet, this);
}

void NetStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    !Corrade::Utility::Debug{} << "stop";
    _running = false;

    _pkt_connection.disconnect();
}

NetStreamHandler::~NetStreamHandler()
{
    !Corrade::Utility::Debug{} << "destroy";
}

void NetStreamHandler::process_packet(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp)
{
    _metrics.process_packet(payload, dir, l3, l4, stamp);
}

void NetStreamHandler::toJSON(json &j, uint64_t period, bool merged)
{
    if (merged) {
        _metrics.toJSONMerged(j["net"], period);
    } else {
        _metrics.toJSONSingle(j["net"], period);
    }
}

void NetworkMetricsBucket::merge(const AbstractMetricsBucket &o)
{

    const auto &other = static_cast<const NetworkMetricsBucket &>(o);
    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _numPackets += other._numPackets;
    _numPackets_UDP += other._numPackets_UDP;
    _numPackets_TCP += other._numPackets_TCP;
    _numPackets_OtherL4 += other._numPackets_OtherL4;
    _numPackets_IPv6 += other._numPackets_IPv6;
    _numPackets_in += other._numPackets_in;
    _numPackets_out += other._numPackets_out;

    _rateSketches.net_rateIn.merge(other._rateSketches.net_rateIn);
    _rateSketches.net_rateOut.merge(other._rateSketches.net_rateOut);

    datasketches::cpc_union merge_srcIPCard;
    merge_srcIPCard.update(_net_srcIPCard);
    merge_srcIPCard.update(other._net_srcIPCard);
    _net_srcIPCard = merge_srcIPCard.get_result();

    datasketches::cpc_union merge_dstIPCard;
    merge_dstIPCard.update(_net_dstIPCard);
    merge_dstIPCard.update(other._net_dstIPCard);
    _net_dstIPCard = merge_dstIPCard.get_result();

    _net_topIPv4.merge(other._net_topIPv4);
    _net_topIPv6.merge(other._net_topIPv6);
    _net_topGeoLoc.merge(other._net_topGeoLoc);
    _net_topASN.merge(other._net_topASN);
}

void NetworkMetricsBucket::toJSON(json &j) const
{

    std::shared_lock r_lock(_mutex);

    j["packets"]["total"] = _numPackets;
    j["packets"]["udp"] = _numPackets_UDP;
    j["packets"]["tcp"] = _numPackets_TCP;
    j["packets"]["other_l4"] = _numPackets_OtherL4;
    j["packets"]["ipv4"] = _numPackets - _numPackets_IPv6;
    j["packets"]["ipv6"] = _numPackets_IPv6;
    j["packets"]["in"] = _numPackets_in;
    j["packets"]["out"] = _numPackets_out;
}

void NetworkMetricsBucket::process_packet(bool deep, pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp)
{
    std::unique_lock w_lock(_mutex);

    _numPackets++;

    switch (dir) {
    case PacketDirection::fromHost:
        _numPackets_out++;
        break;
    case toHost:
        _numPackets_in++;
        break;
    case unknown:
        break;
    }

    switch (l3) {
    case pcpp::IPv6:
        _numPackets_IPv6++;
        break;
    default:
        break;
    }

    switch (l4) {
    case pcpp::UDP:
        _numPackets_UDP++;
        break;
    case pcpp::TCP:
        _numPackets_TCP++;
        break;
    default:
        _numPackets_OtherL4++;
        break;
    }

    if (!deep) {
        return;
    }

#ifdef MMDB_ENABLE
    const GeoDB *geoCityDB = _mmgr.getGeoCityDB();
    const GeoDB *geoASNDB = _mmgr.getGeoASNDB();
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
#endif

    auto IP4layer = payload.getLayerOfType<pcpp::IPv4Layer>();
    auto IP6layer = payload.getLayerOfType<pcpp::IPv6Layer>();
    if (IP4layer) {
        if (dir == toHost) {
            _net_srcIPCard.update(IP4layer->getSrcIpAddress().toInt());
            _net_topIPv4.update(IP4layer->getSrcIpAddress().toInt());
#ifdef MMDB_ENABLE
            if (IPv4tosockaddr(IP4layer->getSrcIpAddress(), &sa4)) {
                if (geoCityDB) {
                    _net_topGeoLoc.update(geoCityDB->getGeoLocString((struct sockaddr *)&sa4));
                }
                if (geoASNDB) {
                    _net_topASN.update(geoASNDB->getASNString((struct sockaddr *)&sa4));
                }
            }
#endif
        } else if (dir == fromHost) {
            _net_dstIPCard.update(IP4layer->getDstIpAddress().toInt());
            _net_topIPv4.update(IP4layer->getDstIpAddress().toInt());
#ifdef MMDB_ENABLE
            if (IPv4tosockaddr(IP4layer->getDstIpAddress(), &sa4)) {
                if (geoCityDB) {
                    _net_topGeoLoc.update(geoCityDB->getGeoLocString((struct sockaddr *)&sa4));
                }
                if (geoASNDB) {
                    _net_topASN.update(geoASNDB->getASNString((struct sockaddr *)&sa4));
                }
            }
#endif
        }
    } else if (IP6layer) {
        if (dir == toHost) {
            _net_srcIPCard.update((void *)IP6layer->getSrcIpAddress().toBytes(), 16);
            _net_topIPv6.update(IP6layer->getSrcIpAddress().toString());
#ifdef MMDB_ENABLE
            if (IPv6tosockaddr(IP6layer->getSrcIpAddress(), &sa6)) {
                if (geoCityDB) {
                    _net_topGeoLoc.update(geoCityDB->getGeoLocString((struct sockaddr *)&sa6));
                }
                if (geoASNDB) {
                    _net_topASN.update(geoASNDB->getASNString((struct sockaddr *)&sa6));
                }
            }
#endif
        } else if (dir == fromHost) {
            _net_dstIPCard.update((void *)IP6layer->getDstIpAddress().toBytes(), 16);
            _net_topIPv6.update(IP6layer->getDstIpAddress().toString());
#ifdef MMDB_ENABLE
            if (IPv6tosockaddr(IP6layer->getDstIpAddress(), &sa6)) {
                if (geoCityDB) {
                    _net_topGeoLoc.update(geoCityDB->getGeoLocString((struct sockaddr *)&sa6));
                }
                if (geoASNDB) {
                    _net_topASN.update(geoASNDB->getASNString((struct sockaddr *)&sa6));
                }
            }
#endif
        }
    }
}

void NetworkMetricsManager::process_packet(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp)
{
    newEvent(stamp);
    _metricBuckets.back()->process_packet(_shouldDeepSample, payload, dir, l3, l4, stamp);
}

}