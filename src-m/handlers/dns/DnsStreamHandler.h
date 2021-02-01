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

namespace pktvisor::handler::dns {

using namespace pktvisor::input::pcap;

class DnsMetricsBucket final : public pktvisor::AbstractMetricsBucket
{
public:
    const uint8_t START_FI_MAP_SIZE = 7; // 2^7 = 128
    const uint8_t MAX_FI_MAP_SIZE = 13;  // 2^13 = 8192

protected:
    mutable std::shared_mutex _mutex;

    datasketches::kll_sketch<uint64_t> _dnsXactFromTimeUs;
    datasketches::kll_sketch<uint64_t> _dnsXactToTimeUs;

    datasketches::cpc_sketch _dns_qnameCard;

    datasketches::frequent_items_sketch<std::string> _dns_topQname2;
    datasketches::frequent_items_sketch<std::string> _dns_topQname3;
    datasketches::frequent_items_sketch<std::string> _dns_topNX;
    datasketches::frequent_items_sketch<std::string> _dns_topREFUSED;
    datasketches::frequent_items_sketch<std::string> _dns_topSRVFAIL;
    datasketches::frequent_items_sketch<uint16_t> _dns_topUDPPort;
    datasketches::frequent_items_sketch<uint16_t> _dns_topQType;
    datasketches::frequent_items_sketch<uint16_t> _dns_topRCode;
    datasketches::frequent_items_sketch<std::string> _dns_slowXactIn;
    datasketches::frequent_items_sketch<std::string> _dns_slowXactOut;

public:
    DnsMetricsBucket()
        : _dnsXactFromTimeUs()
        , _dnsXactToTimeUs()
        , _dns_qnameCard()
        , _dns_topQname2(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_topQname3(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_topNX(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_topREFUSED(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_topSRVFAIL(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_topUDPPort(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_topQType(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_topRCode(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_slowXactIn(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _dns_slowXactOut(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
    {
    }

    // pktvisor::AbstractMetricsBucket
    void specialized_merge(const AbstractMetricsBucket &other) override;
    void toJSON(json &j) const override;

    void process_udp_packet(bool deep, pcpp::UdpLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp);
};

class DnsMetricsManager final : public pktvisor::AbstractMetricsManager<DnsMetricsBucket>
{
public:
    DnsMetricsManager(uint periods, int deepSampleRate)
        : pktvisor::AbstractMetricsManager<DnsMetricsBucket>(periods, deepSampleRate)
    {
    }

#if 0
    void on_period_shift() override
    {
        Corrade::Utility::Debug{} << "period shift";
    }
    void on_period_evict(const DnsMetricsBucket *bucket) override
    {
        Corrade::Utility::Debug{} << "evict: " << bucket->_numPackets;
    }
#endif

    void process_udp_packet(pcpp::UdpLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp);
};

class DnsStreamHandler final : public pktvisor::StreamMetricsHandler<DnsMetricsManager>
{

    PcapInputStream *_stream;

    sigslot::connection _pkt_udp_connection;
    sigslot::connection _start_tstamp_connection;

    void process_udp_packet_cb(pcpp::UdpLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp);
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
