/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once


#include "AbstractMetricsManager.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wrange-loop-analysis"
#include <cpc_sketch.hpp>
#include <frequent_items_sketch.hpp>
#include <kll_sketch.hpp>
#pragma GCC diagnostic pop
#include <Corrade/Utility/Debug.h>
#include <string>

namespace visor::handler::net {

using namespace visor::input::pcap;

class NetworkMetricsBucket final : public visor::AbstractMetricsBucket
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
    datasketches::frequent_items_sketch<std::string> _topIPv6; // TODO OPTIMIZE not very efficient, should switch to 16 byte uint

    // total numPackets is tracked in base class num_events
    struct counters {
        uint64_t UDP = 0;
        uint64_t TCP = 0;
        uint64_t OtherL4 = 0;
        uint64_t IPv4 = 0;
        uint64_t IPv6 = 0;
        uint64_t total_in = 0;
        uint64_t total_out = 0;
    };
    counters _counters;

    Rate _rate_in;
    Rate _rate_out;

public:
    NetworkMetricsBucket()
        : _srcIPCard()
        , _dstIPCard()
        , _topGeoLoc(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _topASN(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _topIPv4(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _topIPv6(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _rate_in()
        , _rate_out()
    {
    }

    // get a copy of the counters
    counters counters() const
    {
        std::shared_lock lock(_mutex);
        return _counters;
    }

    // visor::AbstractMetricsBucket
    void specialized_merge(const AbstractMetricsBucket &other) override;
    void to_json(json &j) const override;
    void to_prometheus(std::stringstream &out, const std::string &key) const override;

    // must be thread safe as it is called from time window maintenance thread
    void on_set_read_only() override
    {
        // stop rate collection
        _rate_in.cancel();
        _rate_out.cancel();
    }

    void process_packet(bool deep, pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4);
};

class NetworkMetricsManager final : public visor::AbstractMetricsManager<NetworkMetricsBucket>
{
public:
    NetworkMetricsManager(uint periods, int deepSampleRate)
        : visor::AbstractMetricsManager<NetworkMetricsBucket>(periods, deepSampleRate)
    {
    }

#if 0
    void on_period_shift() override
    {
        Corrade::Utility::Debug{} << "period shift";
    }
    void on_period_evict(const NetworkMetricsBucket *bucket) override
    {
        Corrade::Utility::Debug{} << "evict: " << bucket->_numPackets;
    }
#endif

    void process_packet(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);
};

class NetStreamHandler final : public visor::StreamMetricsHandler<NetworkMetricsManager>
{

    PcapInputStream *_stream;

    sigslot::connection _pkt_connection;
    sigslot::connection _start_tstamp_connection;
    sigslot::connection _end_tstamp_connection;

    void process_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);
    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

public:
    NetStreamHandler(const std::string &name, PcapInputStream *stream, uint periods, uint deepSampleRate);
    ~NetStreamHandler() override;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "packets";
    }
    void start() override;
    void stop() override;
    void info_json(json &j) const override;

    // visor::StreamHandler
    void window_json(json &j, uint64_t period, bool merged) override;
    void window_prometheus(std::stringstream &out) override;
};

}

