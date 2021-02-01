#ifndef PKTVISORD_DNSSTREAMHANDLER_H
#define PKTVISORD_DNSSTREAMHANDLER_H

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
#include <Corrade/Utility/Debug.h>
#include <string>

namespace pktvisor::handler {

using namespace pktvisor::input::pcap;

class DnsworkMetricsBucket final : public pktvisor::AbstractMetricsBucket
{
public:
    const uint8_t START_FI_MAP_SIZE = 7; // 2^7 = 128
    const uint8_t MAX_FI_MAP_SIZE = 13;  // 2^13 = 8192

protected:
    mutable std::shared_mutex _mutex;

    datasketches::cpc_sketch _srcIPCard;
    datasketches::cpc_sketch _dstIPCard;

    datasketches::frequent_items_sketch<std::string> _topGeoLoc;
    datasketches::frequent_items_sketch<std::string> _topASN;
    datasketches::frequent_items_sketch<uint32_t> _topIPv4;
    datasketches::frequent_items_sketch<std::string> _topIPv6; // TODO not very efficient, should switch to 16 byte uint

    // total numPackets is tracked in base class num_events
    uint64_t _numPackets_UDP = 0;
    uint64_t _numPackets_TCP = 0;
    uint64_t _numPackets_OtherL4 = 0;
    uint64_t _numPackets_IPv6 = 0;
    uint64_t _numPackets_in = 0;
    uint64_t _numPackets_out = 0;

    Rate _rate_in;
    Rate _rate_out;
    Rate _rate_total;

public:
    DnsworkMetricsBucket()
        : _srcIPCard()
        , _dstIPCard()
        , _topGeoLoc(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _topASN(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _topIPv4(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _topIPv6(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _rate_in()
        , _rate_out()
        , _rate_total()
    {
    }

    // pktvisor::AbstractMetricsBucket
    void specialized_merge(const AbstractMetricsBucket &other) override;
    void toJSON(json &j) const override;

    void process_packet(bool deep, pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);
};

class DnsworkMetricsManager final : public pktvisor::AbstractMetricsManager<DnsworkMetricsBucket>
{
public:
    DnsworkMetricsManager(uint periods, int deepSampleRate)
        : pktvisor::AbstractMetricsManager<DnsworkMetricsBucket>(periods, deepSampleRate)
    {
    }

#if 0
    void on_period_shift() override
    {
        Corrade::Utility::Debug{} << "period shift";
    }
    void on_period_evict(const DnsworkMetricsBucket *bucket) override
    {
        Corrade::Utility::Debug{} << "evict: " << bucket->_numPackets;
    }
#endif

    void process_packet(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);
};

class DnsStreamHandler final : public pktvisor::StreamMetricsHandler<DnsworkMetricsManager>
{

    PcapInputStream *_stream;

    sigslot::connection _pkt_connection;
    sigslot::connection _start_tstamp_connection;

    void process_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);
    void set_initial_tstamp(timespec stamp);

public:
    DnsStreamHandler(const std::string &name, PcapInputStream *stream, uint periods, int deepSampleRate);
    ~DnsStreamHandler() override;

    // pktvisor::AbstractModule
    void start() override;
    void stop() override;
    json info_json() const override;

    // pktvisor::StreamMetricsHandler
    void toJSON(json &j, uint64_t period, bool merged) override;
};

}

#endif //PKTVISORD_DNSSTREAMHANDLER_H
