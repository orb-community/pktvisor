/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "DnstapInputStream.h"
#include "MockInputStream.h"
#include "PcapInputStream.h"
#include "SflowInputStream.h"
#include "StreamHandler.h"
#include "ThreadMonitor.h"
#include <Corrade/Utility/Debug.h>
#include <limits>
#include <string>

namespace visor::handler::resources {

using namespace visor::input::pcap;
using namespace visor::input::dnstap;
using namespace visor::input::mock;
using namespace visor::input::sflow;

constexpr double MEASURE_INTERVAL = 10; // in seconds

class InputResourcesMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;

    // total numPackets is tracked in base class num_events
    Quantile<double> _cpu_percentage;
    Quantile<uint64_t> _memory_usage_kb;
    Counter _policies_number;
    Counter _handlers_count;
    bool _merged;

public:
    InputResourcesMetricsBucket()
        : _cpu_percentage("resources", {"cpu_percentage"}, "Quantiles of thread cpu usage")
        , _memory_usage_kb("resources", {"memory_bytes"}, "Quantiles of thread memory usage in bytes")
        , _policies_number("resources", {"policies_attached"}, "Total number of policies attached to the input stream")
        , _handlers_count("resources", {"handlers_attached"}, "Total number of handlers attached to the input stream")
        , _merged(false)
    {
    }

    // visor::AbstractMetricsBucket

    void specialized_merge(const AbstractMetricsBucket &other) override;
    void to_json(json &j) const override;
    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override;

    void process_resources(double cpu_usage, uint64_t memory_usage);
    void process_policies(int16_t policies_number, int16_t handlers_count);
};

class InputResourcesMetricsManager final : public visor::AbstractMetricsManager<InputResourcesMetricsBucket>
{
    uint16_t policies_total;
    uint16_t handlers_total;

public:
    InputResourcesMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<InputResourcesMetricsBucket>(window_config)
        , policies_total(0)
        , handlers_total(0)
    {
    }

    void on_period_shift([[maybe_unused]] timespec stamp, [[maybe_unused]] const InputResourcesMetricsBucket *maybe_expiring_bucket) override
    {
        process_policies(policies_total, handlers_total, true);
    }

    void process_resources(double cpu_usage, uint64_t memory_usage, timespec stamp = timespec());
    void process_policies(int16_t policies_number, int16_t handlers_count, bool self);
};

class InputResourcesStreamHandler final : public visor::StreamMetricsHandler<InputResourcesMetricsManager>
{

    // the input stream sources we support (only one will be in use at a time)
    ThreadMonitor _monitor;
    time_t _timer;
    timespec _timestamp;
    PcapInputStream *_pcap_stream{nullptr};
    DnstapInputStream *_dnstap_stream{nullptr};
    MockInputStream *_mock_stream{nullptr};
    SflowInputStream *_sflow_stream{nullptr};

    sigslot::connection _dnstap_connection;
    sigslot::connection _sflow_connection;
    sigslot::connection _pkt_connection;
    sigslot::connection _policies_connection;

    void process_sflow_cb(const SFSample &);
    void process_dnstap_cb(const dnstap::Dnstap &);
    void process_policies_cb(const Policy *policy, InputStream::Action action);
    void process_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, timespec stamp);

public:
    InputResourcesStreamHandler(const std::string &name, InputStream *stream, const Configurable *window_config, StreamHandler *handler = nullptr);
    ~InputResourcesStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "input_resources";
    }

    size_t consumer_count() const override
    {
        return 0;
    }

    void start() override;
    void stop() override;
};

}
