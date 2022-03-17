/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "ResourcesStreamHandler.h"

namespace visor::handler::resources {

ResourcesStreamHandler::ResourcesStreamHandler(const std::string &name, InputStream *stream, const Configurable *window_config, StreamHandler *handler)
    : visor::StreamMetricsHandler<ResourcesMetricsManager>(name, window_config)
    , _timer(time(NULL))
{
    std::timespec_get(&_timestamp, TIME_UTC);

    if (handler) {
        throw StreamHandlerException(fmt::format("ResourcesStreamHandler: unsupported upstream chained stream handler {}", handler->name()));
    }

    assert(stream);
    // figure out which input stream we have
    if (stream) {
        _pcap_stream = dynamic_cast<PcapInputStream *>(stream);
        _dnstap_stream = dynamic_cast<DnstapInputStream *>(stream);
        _mock_stream = dynamic_cast<MockInputStream *>(stream);
        _sflow_stream = dynamic_cast<SflowInputStream *>(stream);
        if (!_pcap_stream && !_mock_stream && !_dnstap_stream && !_sflow_stream) {
            throw StreamHandlerException(fmt::format("NetStreamHandler: unsupported input stream {}", stream->name()));
        }
    }
}

void ResourcesStreamHandler::start()
{
    if (_running) {
        return;
    }

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    if (_pcap_stream) {
        _pkt_connection = _pcap_stream->packet_signal.connect(&ResourcesStreamHandler::process_packet_cb, this);
    } else if (_dnstap_stream) {
        _dnstap_connection = _dnstap_stream->dnstap_signal.connect(&ResourcesStreamHandler::process_dnstap_cb, this);
    } else if (_sflow_stream) {
        _sflow_connection = _sflow_stream->sflow_signal.connect(&ResourcesStreamHandler::process_sflow_cb, this);
    }

    _running = true;
}

void ResourcesStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    if (_pcap_stream) {
        _pkt_connection.disconnect();
    } else if (_dnstap_stream) {
        _dnstap_connection.disconnect();
    } else if (_sflow_stream) {
        _sflow_connection.disconnect();
    }

    _running = false;
}

void ResourcesStreamHandler::process_sflow_cb([[maybe_unused]] const SFSample &)
{
    if (difftime(time(NULL), _timer) >= MEASURE_INTERVAL) {
        _timer = time(NULL);
        _metrics->process_resources();
    }
}

void ResourcesStreamHandler::process_dnstap_cb([[maybe_unused]] const dnstap::Dnstap &)
{
    if (difftime(time(NULL), _timer) >= MEASURE_INTERVAL) {
        _timer = time(NULL);
        _metrics->process_resources();
    }
}

void ResourcesStreamHandler::process_packet_cb([[maybe_unused]] pcpp::Packet &payload, [[maybe_unused]] PacketDirection dir, [[maybe_unused]] pcpp::ProtocolType l3, [[maybe_unused]] pcpp::ProtocolType l4, [[maybe_unused]] timespec stamp)
{
    if (stamp.tv_sec >= MEASURE_INTERVAL + _timestamp.tv_sec) {
        _timestamp = stamp;
        _metrics->process_resources();
    }
}

void ResourcesMetricsBucket::specialized_merge(const AbstractMetricsBucket &o)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const ResourcesMetricsBucket &>(o);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _cpu_percentage.merge(other._cpu_percentage);
    _memory_usage_kb.merge(other._memory_usage_kb);
}

void ResourcesMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{
    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_prometheus(out, add_labels);
        num_events->to_prometheus(out, add_labels);
        num_samples->to_prometheus(out, add_labels);
    }

    std::shared_lock r_lock(_mutex);

    _cpu_percentage.to_prometheus(out, add_labels);
    _memory_usage_kb.to_prometheus(out, add_labels);
}

void ResourcesMetricsBucket::to_json(json &j) const
{
    bool live_rates = !read_only() && !recorded_stream();

    {
        auto [num_events, num_samples, event_rate, event_lock] = event_data_locked(); // thread safe

        event_rate->to_json(j, live_rates);
        num_events->to_json(j);
        num_samples->to_json(j);
    }

    std::shared_lock r_lock(_mutex);

    _cpu_percentage.to_json(j);
    _memory_usage_kb.to_json(j);
}

void ResourcesMetricsBucket::process_resources()
{
    std::unique_lock lock(_mutex);

    _cpu_percentage.update(_monitor.cpu_percentage());
    _memory_usage_kb.update(_monitor.memory_usage());
}

void ResourcesMetricsManager::process_resources()
{
    timespec stamp;
    // use now()
    std::timespec_get(&stamp, TIME_UTC);
    // base event
    new_event(stamp);
    // process in the "live" bucket. this will parse the resources if we are deep sampling
    live_bucket()->process_resources();
}
}