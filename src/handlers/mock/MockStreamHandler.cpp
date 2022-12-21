/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "MockStreamHandler.h"
#include <spdlog/sinks/stdout_color_sinks.h>

namespace visor::handler::mock {

MockStreamHandler::MockStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config)
    : visor::StreamMetricsHandler<MockMetricsManager>(name, window_config)
{
    assert(proxy);

    _logger = spdlog::get("dyn-mock-handler");
    if (!_logger) {
        _logger = spdlog::stderr_color_mt("dyn-mock-handler");
    }
    assert(_logger);
    // figure out which input event proxy we have
    _mock_proxy = dynamic_cast<MockInputEventProxy *>(proxy);
    if (!_mock_proxy) {
        throw StreamHandlerException(fmt::format("MockStreamHandler: unsupported input event proxy {}", proxy->name()));
    }

    _logger->info("mock handler created");
}
MockStreamHandler::~MockStreamHandler()
{
    _logger->info("mock handler destroyed");
}

void MockStreamHandler::process_random_int(uint64_t i)
{
    _logger->info("mock handler received random int signal: {}", i);
    _metrics->process_random_int(i);
}

void MockStreamHandler::start()
{
    if (_running) {
        return;
    }

    _logger->info("mock handler start()");

    _random_int_connection = _mock_proxy->random_int_signal.connect(&MockStreamHandler::process_random_int, this);

    _running = true;
}

void MockStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    _logger->info("mock handler stop()");

    _running = false;
}

void MockMetricsBucket::specialized_merge(const AbstractMetricsBucket &o, [[maybe_unused]] Metric::Aggregate agg_operator)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const MockMetricsBucket &>(o);

    std::shared_lock r_lock(other._mutex);
    std::unique_lock w_lock(_mutex);

    _counters.mock_counter += other._counters.mock_counter;
}

void MockMetricsBucket::to_prometheus(std::stringstream &out, Metric::LabelMap add_labels) const
{
    std::shared_lock r_lock(_mutex);

    _counters.mock_counter.to_prometheus(out, add_labels);
}

void MockMetricsBucket::to_opentelemetry(metrics::v1::ScopeMetrics &scope, Metric::LabelMap add_labels) const
{
    auto start_ts = start_tstamp();
    auto end_ts = end_tstamp();
    
    std::shared_lock r_lock(_mutex);

    _counters.mock_counter.to_opentelemetry(scope, start_ts, end_ts, add_labels);
}

void MockMetricsBucket::to_json(json &j) const
{
    std::shared_lock r_lock(_mutex);

    _counters.mock_counter.to_json(j);
}
void MockMetricsBucket::process_random_int(uint64_t i)
{
    std::unique_lock w_lock(_mutex);
    _counters.mock_counter += i;
}

void MockMetricsManager::process_random_int(uint64_t i)
{
    live_bucket()->process_random_int(i);
}
}