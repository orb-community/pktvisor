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
    if (type == TestType::Ping) {
        auto icmp = payload.getLayerOfType<pcpp::IcmpLayer>();
        if (icmp != nullptr && icmp->getMessageType() == pcpp::ICMP_ECHO_REPLY) {
            auto stamp = payload.getRawPacket()->getPacketTimeStamp();
            _metrics->process_netprobe_icmp(icmp, name, stamp);
        }
    }
}

void NetProbeStreamHandler::probe_signal_fail([[maybe_unused]] ErrorType error, TestType type, const std::string &name)
{
    _metrics->process_fail_event(name);
}

void NetProbeMetricsBucket::specialized_merge(const AbstractMetricsBucket &o, Metric::Aggregate agg_operator)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const NetProbeMetricsBucket &>(o);

    // rates maintain their own thread safety
    _rate_total.merge(other._rate_total, agg_operator);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _counters.total += other._counters.total;
    _counters.filtered += other._counters.filtered;

    for (const auto &target : other._targets_metrics) {
        const auto &targetId = target.first;

        _targets_metrics[targetId]->fail += target.second->fail;
        _targets_metrics[targetId]->time_ms.merge(target.second->time_ms, agg_operator);
    }
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

    _counters.total.to_prometheus(out, add_labels);
    _counters.filtered.to_prometheus(out, add_labels);

    for (const auto &target : _targets_metrics) {
        auto target_labels = add_labels;
        auto targetId = target.first;
        target_labels["target"] = targetId;

        target.second->fail.to_prometheus(out, target_labels);
        target.second->time_ms.to_prometheus(out, target_labels);
    }
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

    _counters.total.to_json(j);
    _counters.filtered.to_json(j);

    for (const auto &target : _targets_metrics) {
        auto targetId = target.first;

        target.second->fail.to_json(j["targets"][targetId]);
        target.second->time_ms.to_json(j["targets"][targetId]);
    }
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

void NetProbeMetricsBucket::process_netprobe_icmp([[maybe_unused]] bool deep, pcpp::IcmpLayer *layer, std::string target, timespec stamp)
{
    std::unique_lock lock(_mutex);

    ++_counters.total;
    ++_rate_total;

    if (!_targets_metrics.count(target)) {
        _targets_metrics[target] = std::make_unique<Target>();
    }
    bool fail{true};
    if (auto reply = layer->getEchoReplyData(); reply != nullptr && reply->dataLength > validator.size()
        && (std::memcmp(reply->data, validator.data(), validator.size()) == 0)) {
        auto time_sec = static_cast<uint64_t>(stamp.tv_sec);
        if (time_sec > reply->header->timestamp) {
            uint64_t time_ms = (time_sec - reply->header->timestamp) * 1000;
            time_ms += (stamp.tv_nsec / 1000000);
            _targets_metrics[target]->time_ms.update(time_ms);
            fail = false;
        } else if (time_sec == reply->header->timestamp) {
            _targets_metrics[target]->time_ms.update(stamp.tv_nsec / 1000000);
            fail = false;
        }
    }

    if (fail) {
        ++_targets_metrics[target]->fail;
    }
}

void NetProbeMetricsBucket::process_fail_event(std::string target)
{
    if (!_targets_metrics.count(target)) {
        _targets_metrics[target] = std::make_unique<Target>();
    }
    ++_counters.total;
    ++_targets_metrics[target]->fail;
}

void NetProbeMetricsManager::process_netprobe_icmp(pcpp::IcmpLayer *layer, std::string target, timespec stamp)
{
    // base event
    new_event(stamp);
    // process in the "live" bucket. this will parse the resources if we are deep sampling
    live_bucket()->process_netprobe_icmp(_deep_sampling_now, layer, target, stamp);
}

void NetProbeMetricsManager::process_fail_event(std::string target)
{
    timespec stamp;
    // use now()
    std::timespec_get(&stamp, TIME_UTC);
    // base event
    new_event(stamp);

    live_bucket()->process_fail_event(target);
}

void NetProbeMetricsManager::process_filtered(timespec stamp)
{
    // base event, no sample
    new_event(stamp, false);
    live_bucket()->process_filtered();
}

}