/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "NetProbeStreamHandler.h"

namespace visor::handler::netprobe {

NetProbeStreamHandler::NetProbeStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config)
    : visor::StreamMetricsHandler<NetProbeMetricsManager>(name, window_config)
{
    assert(proxy);
    // figure out which input event proxy we have
    _netprobe_proxy = dynamic_cast<NetProbeInputEventProxy *>(proxy);
    if (!_netprobe_proxy) {
        throw StreamHandlerException(fmt::format("NetProbeStreamHandler: unsupported input event proxy {}", proxy->name()));
    }
}

void NetProbeStreamHandler::start()
{
    if (_running) {
        return;
    }

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    if (_netprobe_proxy) {
        _probe_recv_connection = _netprobe_proxy->probe_recv_signal.connect(&NetProbeStreamHandler::probe_signal_recv, this);
        _probe_fail_connection = _netprobe_proxy->probe_fail_signal.connect(&NetProbeStreamHandler::probe_signal_fail, this);
        _heartbeat_connection = _netprobe_proxy->heartbeat_signal.connect(&NetProbeStreamHandler::check_period_shift, this);
    }

    _running = true;
}

void NetProbeStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    if (_netprobe_proxy) {
        _probe_recv_connection.disconnect();
        _probe_fail_connection.disconnect();
        _heartbeat_connection.disconnect();
    }

    _running = false;
}

void NetProbeStreamHandler::probe_signal_recv(pcpp::Packet &payload, TestType type, const std::string &name)
{
}

void NetProbeStreamHandler::probe_signal_fail(pcpp::Packet &payload, TestType type, const std::string &name)
{
}

void NetProbeMetricsBucket::specialized_merge(const AbstractMetricsBucket &o, Metric::Aggregate agg_operator)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const NetProbeMetricsBucket &>(o);

    // rates maintain their own thread safety
    _rate_total.merge(other._rate_total, agg_operator);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _counters.OPEN += other._counters.OPEN;
    _counters.UPDATE += other._counters.UPDATE;
    _counters.total += other._counters.total;
    _counters.filtered += other._counters.filtered;
}

void NetProbeMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{

    _rate_total.to_prometheus(out, add_labels);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_prometheus(out, add_labels);
        num_events->to_prometheus(out, add_labels);
        num_samples->to_prometheus(out, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    _counters.OPEN.to_prometheus(out, add_labels);
    _counters.UPDATE.to_prometheus(out, add_labels);
    _counters.total.to_prometheus(out, add_labels);
    _counters.filtered.to_prometheus(out, add_labels);
}

void NetProbeMetricsBucket::to_json(json &j) const
{

    bool live_rates = !read_only() && !recorded_stream();
    _rate_total.to_json(j, live_rates);

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_json(j, live_rates);
        num_events->to_json(j);
        num_samples->to_json(j);
    }

    std::shared_lock r_lock(_mutex);

    _counters.OPEN.to_json(j);
    _counters.UPDATE.to_json(j);
    _counters.total.to_json(j);
    _counters.filtered.to_json(j);
}

void NetProbeMetricsBucket::process_filtered()
{
    std::unique_lock lock(_mutex);
    ++_counters.filtered;
}

bool NetProbeStreamHandler::_filtering([[maybe_unused]] pcpp::Packet *payload)
{
    // no filters yet
    return false;
}

void NetProbeMetricsBucket::process_netprobe([[maybe_unused]] bool deep, pcpp::Packet *payload)
{
    std::unique_lock lock(_mutex);

    ++_counters.total;
    ++_rate_total;

    ++_counters.OPEN;
    ++_counters.UPDATE;
}

void NetProbeMetricsManager::process_netprobe(pcpp::Packet *payload, timespec stamp)
{
    // base event
    new_event(stamp);
    // process in the "live" bucket. this will parse the resources if we are deep sampling
    live_bucket()->process_netprobe(_deep_sampling_now, payload);
}

void NetProbeMetricsManager::process_filtered(timespec stamp)
{
    // base event, no sample
    new_event(stamp, false);
    live_bucket()->process_filtered();
}

}