#ifndef PKTVISORD_STREAMHANDLER_H
#define PKTVISORD_STREAMHANDLER_H

#include "AbstractMetricsManager.h"
#include "AbstractModule.h"
#include <json/json.hpp>

namespace pktvisor {

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

    virtual ~StreamMetricsHandler(){};

    virtual void toJSON(json &j, uint64_t period, bool merged) = 0;
};

}

#endif //PKTVISORD_STREAMHANDLER_H
