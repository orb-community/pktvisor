/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "DhcpInputStream.h"
#include "StreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <limits>
#include <string>

namespace visor::handler::dhcp {

using namespace visor::input::dhcp;

class DhcpMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;

    // total numPackets is tracked in base class num_events
    struct counters {

        Counter dhcp_TCP_reassembly_errors;

        Counter dhcp_os_drop;
        uint64_t dhcp_last_os_drop{std::numeric_limits<uint64_t>::max()};

        Counter dhcp_if_drop;
        uint64_t dhcp_last_if_drop{std::numeric_limits<uint64_t>::max()};

        counters()
            : dhcp_TCP_reassembly_errors("dhcp", {"tcp_reassembly_errors"}, "Count of TCP reassembly errors")
            , dhcp_os_drop("dhcp", {"os_drops"}, "Count of packets dropped by the operating system (if supported)")
            , dhcp_if_drop("dhcp", {"if_drops"}, "Count of packets dropped by the interface (if supported)")
        {
        }
    };
    counters _counters;

public:
    DhcpMetricsBucket()
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

    void process_dhcp_tcp_reassembly_error(bool deep, pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3);
    void process_dhcp_stats(const pcpp::IDhcpDevice::DhcpStats &stats);
};

class DhcpMetricsManager final : public visor::AbstractMetricsManager<DhcpMetricsBucket>
{
public:
    DhcpMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<DhcpMetricsBucket>(window_config)
    {
    }

    void process_dhcp_tcp_reassembly_error(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, timespec stamp);
    void process_dhcp_stats(const pcpp::IDhcpDevice::DhcpStats &stats);
};

class DhcpStreamHandler final : public visor::StreamMetricsHandler<DhcpMetricsManager>
{

    DhcpInputStream *_dhcp_stream;

    sigslot::connection _start_tstamp_connection;
    sigslot::connection _end_tstamp_connection;

    sigslot::connection _dhcp_tcp_reassembly_errors_connection;
    sigslot::connection _dhcp_stats_connection;

    void process_dhcp_tcp_reassembly_error(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, timespec stamp);
    void process_dhcp_stats(const pcpp::IDhcpDevice::DhcpStats &stats);

    void set_start_tstamp(timespec stamp);
    void set_end_tstamp(timespec stamp);

public:
    DhcpStreamHandler(const std::string &name, InputStream *stream, const Configurable *window_config);
    ~DhcpStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "dhcp";
    }
    void start() override;
    void stop() override;
};

}
