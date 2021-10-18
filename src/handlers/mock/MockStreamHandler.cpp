/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "MockStreamHandler.h"

namespace visor::handler::mock {

MockStreamHandler::MockStreamHandler(const std::string &name, InputStream *stream, const Configurable *window_config)
    : visor::StreamMetricsHandler<MockMetricsManager>(name, window_config)
{
    assert(stream);
    // figure out which input stream we have
    _mock_stream = dynamic_cast<MockInputStream *>(stream);
    if (!_mock_stream) {
        throw StreamHandlerException(fmt::format("MockStreamHandler: unsupported input stream {}", stream->name()));
    }
}

void MockStreamHandler::start()
{
    if (_running) {
        return;
    }

    if (config_exists("recorded_stream")) {
        _metrics->set_recorded_stream();
    }

    _running = true;
}

void MockStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    _running = false;
}

void MockMetricsBucket::specialized_merge(const AbstractMetricsBucket &o)
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

void MockMetricsBucket::to_json(json &j) const
{
    std::shared_lock r_lock(_mutex);

    _counters.mock_counter.to_json(j);
}

}