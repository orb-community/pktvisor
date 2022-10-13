/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "NetProbeInputStream.h"
#include "RequestReplyManager.h"
#include "StreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <IcmpLayer.h>
#include <limits>
#include <string>

namespace visor::handler::netprobe {

using namespace visor::input::netprobe;

static constexpr const char *NET_PROBE_SCHEMA{"netprobe"};

struct Target {
    Quantile<uint64_t> time_us;
    Counter attempts;
    Counter successes;
    Counter minimum;
    Counter maximum;

    Target()
        : time_us(NET_PROBE_SCHEMA, {"response_quantiles_us"}, "Net Probe quantile in microseconds")
        , attempts(NET_PROBE_SCHEMA, {"attempts"}, "Total Net Probe attempts")
        , successes(NET_PROBE_SCHEMA, {"successes"}, "Total Net Probe successes")
        , minimum(NET_PROBE_SCHEMA, {"response_min_us"}, "Minimum response time measured in the reporting interval")
        , maximum(NET_PROBE_SCHEMA, {"response_max_us"}, "Maximum response time measured in the reporting interval")
    {
    }
};

class NetProbeMetricsBucket final : public visor::AbstractMetricsBucket
{

protected:
    mutable std::shared_mutex _mutex;
    std::map<std::string, std::unique_ptr<Target>> _targets_metrics;

public:
    NetProbeMetricsBucket()
    {
    }

    // visor::AbstractMetricsBucket
    void specialized_merge(const AbstractMetricsBucket &other, Metric::Aggregate agg_operator) override;
    void to_json(json &j) const override;
    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override;
    void update_topn_metrics(size_t, uint64_t) override
    {
    }

    void on_set_read_only() override
    {
    }

    void process_filtered();
    void process_netprobe_icmp(bool deep, pcpp::IcmpLayer *layer, const std::string &target);
    void new_icmp_transaction(bool deep, NetProbeTransaction xact);
};

class NetProbeMetricsManager final : public visor::AbstractMetricsManager<NetProbeMetricsBucket>
{
    std::map<std::string, RequestReplyManager> _request_reply_manager_list;

public:
    NetProbeMetricsManager(const Configurable *window_config)
        : visor::AbstractMetricsManager<NetProbeMetricsBucket>(window_config)
    {
    }

    void on_period_shift(timespec stamp, [[maybe_unused]] const NetProbeMetricsBucket *maybe_expiring_bucket) override
    {
        // NetProbe transaction support
        for (auto &target : _request_reply_manager_list) {
            target.second.purge_old_transactions(stamp);
        }
    }

    void process_filtered(timespec stamp);
    void process_netprobe_icmp(pcpp::IcmpLayer *layer, const std::string &target, timespec stamp);
};

class NetProbeStreamHandler final : public visor::StreamMetricsHandler<NetProbeMetricsManager>
{

    NetProbeInputEventProxy *_netprobe_proxy;

    sigslot::connection _probe_send_connection;
    sigslot::connection _probe_recv_connection;
    sigslot::connection _probe_fail_connection;
    sigslot::connection _heartbeat_connection;

    void probe_signal_send(pcpp::Packet &, TestType, const std::string &, timespec);
    void probe_signal_recv(pcpp::Packet &, TestType, const std::string &, timespec);
    void probe_signal_fail(ErrorType, TestType, const std::string &);

    bool _filtering(pcpp::Packet *payload);

public:
    NetProbeStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config);
    ~NetProbeStreamHandler() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return NET_PROBE_SCHEMA;
    }

    void start() override;
    void stop() override;
};

}
