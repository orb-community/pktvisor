#include "NetStreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <Corrade/Utility/DebugStl.h>

#include <datasketches/datasketches/cpc/cpc_union.hpp>

namespace pktvisor {
namespace handler {

NetStreamHandler::NetStreamHandler(const std::string &name, pktvisor::input::PcapInputStream *stream)
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

void NetStreamHandler::process_packet(pcpp::Packet &payload)
{
    Corrade::Utility::Debug{} << _name << ":" << payload.toString();
    _metrics.process_packet(payload);
}

void NetStreamHandler::toJSON(json &j, uint64_t period, bool merged)
{
    _metrics.toJSONSingle(j["net"], period);
}

void NetworkMetricsBucket::merge(NetworkMetricsBucket &other)
{

    _numPackets += other._numPackets;
    _numPackets_UDP += other._numPackets_UDP;
    _numPackets_TCP += other._numPackets_TCP;
    _numPackets_OtherL4 += other._numPackets_OtherL4;
    _numPackets_IPv6 += other._numPackets_IPv6;
    _numPackets_in += other._numPackets_in;
    _numPackets_out += other._numPackets_out;

    // lock me for for write, other for read/
    /*
    std::unique_lock w_lock(_sketchMutex);
    std::shared_lock r_lock(other._sketchMutex);
    std::unique_lock w_lock_r(_rateSketchMutex);
    std::shared_lock r_lock_r(other._rateSketchMutex);
     */

    _rateSketches.net_rateIn.merge(other._rateSketches.net_rateIn);
    _rateSketches.net_rateOut.merge(other._rateSketches.net_rateOut);

    datasketches::cpc_union merge_srcIPCard;
    merge_srcIPCard.update(_sketches->_net_srcIPCard);
    merge_srcIPCard.update(other._sketches->_net_srcIPCard);
    _sketches->_net_srcIPCard = merge_srcIPCard.get_result();

    datasketches::cpc_union merge_dstIPCard;
    merge_dstIPCard.update(_sketches->_net_dstIPCard);
    merge_dstIPCard.update(other._sketches->_net_dstIPCard);
    _sketches->_net_dstIPCard = merge_dstIPCard.get_result();

    _sketches->_net_topIPv4.merge(other._sketches->_net_topIPv4);
    _sketches->_net_topIPv6.merge(other._sketches->_net_topIPv6);
    _sketches->_net_topGeoLoc.merge(other._sketches->_net_topGeoLoc);
    _sketches->_net_topASN.merge(other._sketches->_net_topASN);
}

void NetworkMetricsBucket::process_packet(pcpp::Packet &payload)
{
    _numPackets++;
}

void NetworkMetricsBucket::toJSON(json &j)
{
    // lock for read
    std::shared_lock lock_sketch(_sketchMutex);
    std::shared_lock lock_rate(_rateSketchMutex);

    j["packets"]["total"] = _numPackets;
    j["packets"]["udp"] = _numPackets_UDP;
    j["packets"]["tcp"] = _numPackets_TCP;
    j["packets"]["other_l4"] = _numPackets_OtherL4;
    j["packets"]["ipv4"] = _numPackets - _numPackets_IPv6;
    j["packets"]["ipv6"] = _numPackets_IPv6;
    j["packets"]["in"] = _numPackets_in;
    j["packets"]["out"] = _numPackets_out;
}

void NetworkMetricsManager::process_packet(pcpp::Packet &payload)
{
    // at each new packet, we determine if we are sampling, to limit collection of more detailed (expensive) statistics
    _shouldDeepSample = true;
    if (_deepSampleRate != 100) {
        _shouldDeepSample = (_rng.uniform(0, 100) <= _deepSampleRate);
    }
    if (!_singleSummaryMode) {
        // use packet timestamps to track when PERIOD_SEC passes so we don't have to hit system clock
        auto pkt_ts = payload.getRawPacketReadOnly()->getPacketTimeStamp();
        if (pkt_ts.tv_sec - _lastShiftTS.tv_sec > AbstractMetricsManager::PERIOD_SEC) {
            _periodShift();
            _lastShiftTS.tv_sec = pkt_ts.tv_sec;
            //pairMgr.purgeOldTransactions(pkt_ts);
            //_openDnsTransactionCount = pairMgr.getOpenTransactionCount();
        } /*
        switch (dir) {
        case fromHost:
            _instantRates->_rate_out.incCounter();
            break;
        case toHost:
            _instantRates->_rate_in.incCounter();
            break;
        case unknown:
            break;
        }*/
    }
    _metricBuckets.back()->process_packet(payload);
}

}
}