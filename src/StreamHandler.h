/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "AbstractModule.h"
#include <nlohmann/json.hpp>
#include <sstream>

namespace visor {

using json = nlohmann::json;

class StreamHandlerException : public std::runtime_error
{
public:
    explicit StreamHandlerException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

class StreamHandler : public AbstractRunnableModule
{

public:
    StreamHandler(const std::string &name)
        : AbstractRunnableModule(name)
    {
    }

    virtual ~StreamHandler(){};

    virtual size_t consumer_count() const = 0;
    virtual void window_json(json &j, uint64_t period, bool merged) = 0;
    virtual void window_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) = 0;
};

template <class MetricsManagerClass>
class StreamMetricsHandler : public StreamHandler
{

protected:
    std::unique_ptr<MetricsManagerClass> _metrics;

    void common_info_json(json &j) const
    {
        AbstractRunnableModule::common_info_json(j);

        j["metrics"]["deep_sample_rate"] = _metrics->deep_sample_rate();
        j["metrics"]["periods_configured"] = _metrics->num_periods();

        j["metrics"]["periods"] = json::array();
        for (auto i = 0UL; i < _metrics->current_periods(); ++i) {
            {
                std::stringstream ssts;
                time_t b_time_t = _metrics->bucket(i)->start_tstamp().tv_sec;
                ssts << std::put_time(std::gmtime(&b_time_t), "%Y-%m-%d %X");
                j["metrics"]["periods"][i]["start_tstamp"] = ssts.str();
            }
            if (_metrics->bucket(i)->read_only()) {
                std::stringstream ssts;
                time_t b_time_t = _metrics->bucket(i)->end_tstamp().tv_sec;
                ssts << std::put_time(std::gmtime(&b_time_t), "%Y-%m-%d %X");
                j["metrics"]["periods"][i]["end_tstamp"] = ssts.str();
            }
            j["metrics"]["periods"][i]["read_only"] = _metrics->bucket(i)->read_only();
            j["metrics"]["periods"][i]["length"] = _metrics->bucket(i)->period_length();
            auto [num_events, num_samples, event_rate, event_lock] = _metrics->bucket(i)->event_data_locked();
            num_events->to_json(j["metrics"]["periods"][i]["events"]);
            num_samples->to_json(j["metrics"]["periods"][i]["events"]);
            event_rate->to_json(j["metrics"]["periods"][i]["events"]["rates"], !_metrics->bucket(i)->read_only());
        }
    }

public:
    StreamMetricsHandler(const std::string &name, const Configurable *window_config, const std::bitset<64> groups = std::bitset<64>())
        : StreamHandler(name)
    {
        _metrics = std::make_unique<MetricsManagerClass>(window_config, groups);
    }

    const MetricsManagerClass *metrics() const
    {
        return _metrics.get();
    }

    void window_json(json &j, uint64_t period, bool merged) override
    {
        if (merged) {
            _metrics->window_merged_json(j, schema_key(), period);
        } else {
            _metrics->window_single_json(j, schema_key(), period);
        }
    }

    void window_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) override
    {
        if (_metrics->current_periods() > 1) {
            _metrics->window_single_prometheus(out, 1, add_labels);
        } else {
            _metrics->window_single_prometheus(out, 0, add_labels);
        }
    }

    virtual ~StreamMetricsHandler(){};
};

}
