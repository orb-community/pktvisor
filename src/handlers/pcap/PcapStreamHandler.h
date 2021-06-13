/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "PcapInputStream.h"
#include "StreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <limits>
#include <string>

namespace visor::handler::pcap {

using namespace visor::input::pcap;

class PcapMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;

    // total numPackets is tracked in base class num_events
    struct counters {

        Counter pcap_TCP_reassembly_errors;

        Counter pcap_os_drop;
        uint64_t pcap_last_os_drop{std::numeric_limits<uint64_t>::max()};

        Counter pcap_if_drop;
        uint64_t pcap_last_if_drop{std::numeric_limits<uint64_t>::max()};

        counters()
            : pcap_TCP_reassembly_errors("pcap", {"tcp_reassembly_errors"}, "Count of TCP reassembly errors")
            , pcap_os_drop("pcap", {"os_drops"}, "Count of packets dropped by the operating system (if supported)")
            , pcap_if_drop("pcap", {"if_drops"}, "Count of packets dropped by the interface (if supported)")
        {
        }
    };
    counters _counters;

public:
    PcapMetricsBucket()
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
    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override;

    void process_pcap_tcp_reassembly_error(bool deep, pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3);
    void process_pcap_stats(const pcpp::IPcapDevice::PcapStats &stats);
};

class PcapMetricsManager final : public visor::AbstractMetricsManager<PcapMetricsBucket>
{
public:
    PcapMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<PcapMetricsBucket>(window_config)
    {
    }

    void process_pcap_tcp_reassembly_error(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, timespec stamp);
    void process_pcap_stats(const pcpp::IPcapDevice::PcapStats &stats);
};

class PcapStreamHandler final : public visor::StreamMetricsHandler<PcapMetricsManager>
{

    PcapInputStream *_pcap_stream;

    sigslot::connection _start_tstamp_connection;
    sigslot::connection _end_tstamp_connection;

    sigslot::connection _pcap_tcp_reassembly_errors_connection;
    sigslot::connection _pcap_stats_connection;

    void process_pcap_tcp_reassembly_error(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, timespec stamp);
    void process_pcap_stats(const pcpp::IPcapDevice::PcapStats &stats);

    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

public:
    PcapStreamHandler(const std::string &name, InputStream *stream, const Configurable *window_config);
    ~PcapStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "pcap";
    }
    void start() override;
    void stop() override;
};

}
