#ifndef VIZERD_STREAMHANDLER_H
#define VIZERD_STREAMHANDLER_H

#include "AbstractMetricsManager.h"
#include "AbstractModule.h"
#include <json/json.hpp>

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
};

template <class MetricsManagerClass>
class StreamMetricsHandler : public StreamHandler
{

protected:
    std::unique_ptr<MetricsManagerClass> _metrics;

public:
    StreamMetricsHandler(const std::string &name, uint periods, int deepSampleRate)
        : StreamHandler(name)
    {
        _metrics = std::make_unique<MetricsManagerClass>(periods, deepSampleRate);
    }

    const MetricsManagerClass* metrics() { return _metrics.get(); }

    virtual ~StreamMetricsHandler(){};

    virtual void to_json(json &j, uint64_t period, bool merged) = 0;
};

}

#endif //VIZERD_STREAMHANDLER_H
