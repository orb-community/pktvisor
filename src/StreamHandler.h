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
        j["metrics"]["periods"] = _metrics->num_periods();
        j["metrics"]["current_periods"] = _metrics->current_periods();
    }

public:
    StreamMetricsHandler(const std::string &name, uint periods, int deepSampleRate)
        : StreamHandler(name)
    {
        _metrics = std::make_unique<MetricsManagerClass>(periods, deepSampleRate);
    }

    const MetricsManagerClass *metrics()
    {
        return _metrics.get();
    }

    virtual ~StreamMetricsHandler(){};
};

}
