#ifndef PKTVISORD_NETSTREAMHANDLER_H
#define PKTVISORD_NETSTREAMHANDLER_H

#include "AbstractMetricsManager.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-function"
#include <datasketches/cpc/cpc_sketch.hpp>
#include <datasketches/fi/frequent_items_sketch.hpp>
#include <datasketches/kll/kll_sketch.hpp>
#pragma GCC diagnostic pop
#include <string>

namespace pktvisor {
namespace handler {

using namespace pktvisor::input::pcap;

struct NetworkRateSketches {
    Rate::QuantileType net_rateIn;
    Rate::QuantileType net_rateOut;
};

class NetworkMetricsBucket : public pktvisor::AbstractMetricsBucket
{
public:
    const uint8_t START_FI_MAP_SIZE = 7; // 2^7 = 128
    const uint8_t MAX_FI_MAP_SIZE = 13;  // 2^13 = 8192

    datasketches::cpc_sketch _net_srcIPCard;
    datasketches::cpc_sketch _net_dstIPCard;

    datasketches::frequent_items_sketch<std::string> _net_topGeoLoc;
    datasketches::frequent_items_sketch<std::string> _net_topASN;
    datasketches::frequent_items_sketch<uint32_t> _net_topIPv4;
    datasketches::frequent_items_sketch<std::string> _net_topIPv6; // TODO not very efficient, should switch to 16 byte uint

    uint64_t _numPackets = 0;
    uint64_t _numPackets_UDP = 0;
    uint64_t _numPackets_TCP = 0;
    uint64_t _numPackets_OtherL4 = 0;
    uint64_t _numPackets_IPv6 = 0;
    uint64_t _numPackets_in = 0;
    uint64_t _numPackets_out = 0;

    NetworkRateSketches _rateSketches;

public:
    NetworkMetricsBucket()
        : _net_srcIPCard()
        , _net_dstIPCard()
        , _net_topGeoLoc(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _net_topASN(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _net_topIPv4(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _net_topIPv6(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
    {
    }

    // pktvisor::AbstractMetricsBucket
    void merge(const AbstractMetricsBucket &other) override;
    void toJSON(json &j) override;

    void process_packet(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);
};

class NetworkMetricsManager : public pktvisor::AbstractMetricsManager<NetworkMetricsBucket>
{
public:
    NetworkMetricsManager(bool singleSummaryMode, uint periods, int deepSampleRate)
        : pktvisor::AbstractMetricsManager<NetworkMetricsBucket>(singleSummaryMode, periods, deepSampleRate)
    {
    }

    void process_packet(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);
};

class NetStreamHandler : public pktvisor::StreamHandler
{

    PcapInputStream *_stream;
    NetworkMetricsManager _metrics;

    sigslot::connection _pkt_connection;

    void process_packet(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);

public:
    NetStreamHandler(const std::string &name, PcapInputStream *stream);
    virtual ~NetStreamHandler();

    // pktvisor::AbstractModule
    void start() override;
    void stop() override;

    // pktvisor::StreamHandler
    void toJSON(json &j, uint64_t period, bool merged) override;
};

}
}

#endif //PKTVISORD_NETSTREAMHANDLER_H
