/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractMetricsManager.h"
#include "AbstractModule.h"
#include <fmt/ostream.h>
#include <nlohmann/json.hpp>
#include <sstream>

namespace visor {

using json = nlohmann::json;

struct CacheHandler {
    std::string schema_key;
    std::string filter_hash;
    timespec timestamp;

    CacheHandler(std::string schema_key, std::string filter_hash, timespec timestamp)
        : schema_key(schema_key)
        , filter_hash(filter_hash)
        , timestamp(timestamp)
    {
    }
};

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
public:
    typedef std::map<std::string, MetricGroupIntType> GroupDefType;

private:
    MetricGroupIntType _process_group(const GroupDefType &group_defs, const std::string &group)
    {
        auto it = group_defs.find(group);
        if (it == group_defs.end()) {
            std::vector<std::string> valid_groups;
            for (const auto &defs : group_defs) {
                valid_groups.push_back(defs.first);
            }
            throw StreamHandlerException(fmt::format("{} is an invalid/unsupported metric group. The valid groups are {}", group, fmt::join(valid_groups, ", ")));
        }
        return it->second;
    }

protected:
    std::unique_ptr<MetricsManagerClass> _metrics;
    std::bitset<GROUP_SIZE> _groups;
    std::string _filter_hash;

    void process_groups(const GroupDefType &group_defs)
    {

        if (config_exists("enable")) {
            for (const auto &group : config_get<StringList>("enable")) {
                _groups.set(_process_group(group_defs, group));
            }
        }

        if (config_exists("disable")) {
            for (const auto &group : config_get<StringList>("disable")) {
                _groups.reset(_process_group(group_defs, group));
            }
        }

        _metrics->configure_groups(&_groups);
    }

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
    StreamMetricsHandler(const std::string &name, const Configurable *window_config)
        : StreamHandler(name)
    {
        _metrics = std::make_unique<MetricsManagerClass>(window_config);
        _metrics->cache_signal.connect(&StreamMetricsHandler::on_cache_callback, this);
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

    virtual void on_cache_callback(CacheHandler &cache) = 0;

    virtual ~StreamMetricsHandler(){};
};

}
