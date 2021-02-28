/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "AbstractModule.h"
#include <nlohmann/json.hpp>

namespace vizer {

using json = nlohmann::json;

class StreamHandler : public AbstractModule
{

public:
    StreamHandler(const std::string &name)
        : AbstractModule(name)
    {
    }

    virtual ~StreamHandler(){};

    virtual void window_json(json &j, uint64_t period, bool merged) = 0;
};

template <class MetricsManagerClass>
class StreamMetricsHandler : public StreamHandler
{

protected:
    std::unique_ptr<MetricsManagerClass> _metrics;

    void _common_info_json(json &j) const
    {
        AbstractModule::_common_info_json(j);
        std::stringstream ss;
        auto in_time_t = std::chrono::system_clock::to_time_t(_metrics->start_time());
        ss << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%d %X");
        j["metrics"]["start_time"] = ss.str();
        j["metrics"]["deep_sample_rate"] = _metrics->deep_sample_rate();
        j["metrics"]["periods_configured"] = _metrics->num_periods();
        j["metrics"]["periods"] = json::array();
        const double fractions[4]{0.50, 0.90, 0.95, 0.99};
        for (int i = 0; i < _metrics->current_periods(); ++i) {
            std::stringstream ssts;
            time_t b_time_t = _metrics->bucket(i)->getTS().tv_sec;
            ssts << std::put_time(std::gmtime(&b_time_t), "%Y-%m-%d %X");
            j["metrics"]["periods"][i]["start_time"] = ssts.str();
            j["metrics"]["periods"][i]["read_only"] = _metrics->bucket(i)->read_only();     // thread safe
            auto [num_events, num_samples, event_rate] = _metrics->bucket(i)->event_data(); // thread safe
            j["metrics"]["periods"][i]["events"]["total"] = num_events;
            j["metrics"]["periods"][i]["events"]["deep_samples"] = num_samples;
            j["metrics"]["periods"][i]["events"]["rates"]["live"] = event_rate->rate();
            auto [rate_quantile, rate_lock] = event_rate->quantile_get_rlocked();
            auto quantiles = rate_quantile->get_quantiles(fractions, 4);
            if (quantiles.size()) {
                j["metrics"]["periods"][i]["events"]["rates"]["p50"] = quantiles[0];
                j["metrics"]["periods"][i]["events"]["rates"]["p90"] = quantiles[1];
                j["metrics"]["periods"][i]["events"]["rates"]["p95"] = quantiles[2];
                j["metrics"]["periods"][i]["events"]["rates"]["p99"] = quantiles[3];
            }
        }
    }

public:
    StreamMetricsHandler(const std::string &name, uint periods, int deepSampleRate, bool realtime = true)
        : StreamHandler(name)
    {
        _metrics = std::make_unique<MetricsManagerClass>(periods, deepSampleRate, realtime);
    }

    const MetricsManagerClass *metrics() const
    {
        return _metrics.get();
    }

    virtual ~StreamMetricsHandler(){};
};

}
