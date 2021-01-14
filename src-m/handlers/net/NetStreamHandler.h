#ifndef PKTVISORD_NETSTREAMHANDLER_H
#define PKTVISORD_NETSTREAMHANDLER_H

#include "MetricsManager.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#include <datasketches/cpc/cpc_sketch.hpp>
#include <datasketches/fi/frequent_items_sketch.hpp>
#include <datasketches/kll/kll_sketch.hpp>
#include <string>

namespace pktvisor {
namespace handler {

struct NetworkRateSketches {
    Rate::QuantileType net_rateIn;
    Rate::QuantileType net_rateOut;
};

struct NetworkSketches {
    const uint8_t START_FI_MAP_SIZE = 7; // 2^7 = 128
    const uint8_t MAX_FI_MAP_SIZE = 13;  // 2^13 = 8192

    datasketches::cpc_sketch _net_srcIPCard;
    datasketches::cpc_sketch _net_dstIPCard;

    datasketches::frequent_items_sketch<std::string> _net_topGeoLoc;
    datasketches::frequent_items_sketch<std::string> _net_topASN;

    NetworkSketches()
        : _net_srcIPCard()
        , _net_dstIPCard()
        , _net_topGeoLoc(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _net_topASN(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
    {
    }
};

class NetworkMetrics : public pktvisor::Metrics<NetworkSketches>
{

    uint64_t _numPackets = 0;
    uint64_t _numPackets_UDP = 0;
    uint64_t _numPackets_TCP = 0;
    uint64_t _numPackets_OtherL4 = 0;
    uint64_t _numPackets_IPv6 = 0;
    uint64_t _numPackets_in = 0;
    uint64_t _numPackets_out = 0;

    /*    // TODO don't need unique_ptr anymore?
    std::unique_ptr<NetworkSketches> _sketches;
    std::shared_mutex _sketchMutex;*/

    NetworkRateSketches _rateSketches;
    std::shared_mutex _rateSketchMutex;

public:
    NetworkMetrics(pktvisor::MetricsManager<NetworkSketches> &mmgr);

    void merge(pktvisor::Metrics<NetworkSketches> &other);
};

class NetStreamHandler : public pktvisor::StreamHandler
{

    pktvisor::input::PcapInputStream *_stream;

    sigslot::connection _pkt_connection;

    void process_packet(pcpp::Packet &payload);

public:
    NetStreamHandler(const std::string &name, pktvisor::input::PcapInputStream *stream);
    virtual ~NetStreamHandler();

    void start() override;
    void stop() override;
};

}
}

#endif //PKTVISORD_NETSTREAMHANDLER_H
