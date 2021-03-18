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
        Counter UDP;
        Counter TCP;
        Counter OtherL4;
        Counter IPv4;
        Counter IPv6;
        Counter total_in;
        Counter total_out;
        counters()
            : UDP("udp", "Count of UDP packets")
            , TCP("tcp", "Count of TCP packets")
            , OtherL4("other_l4", "Count of packets which are not UDP or TCP")
            , IPv4("ipv4", "Count of IPv4 packets")
            , IPv6("ipv6", "Count of IPv6 packets")
            , total_in("in", "Count of total ingress packets")
            , total_out("out", "Count of total egress packets")
        {
        }
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
        , _rate_in("pps_in", "Rate of ingress in packets per second")
        , _rate_out("pps_out", "Rate of egress in packets per second")
    {
        set_event_rate_info("pps_total", "Rate of all packets in packets per second");
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
