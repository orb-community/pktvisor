#ifndef PKTVISORD_STREAMHANDLER_H
#define PKTVISORD_STREAMHANDLER_H

#include "AbstractModule.h"
#include <json/json.hpp>

using json = nlohmann::json;

namespace pktvisor {

class StreamHandler : public AbstractModule
{

public:
    StreamHandler(const std::string &name)
        : AbstractModule(name)
    {
    }

    virtual ~StreamHandler(){};

    virtual void toJSON(json &j, uint64_t period, bool merged) = 0;
};

}

#endif //PKTVISORD_STREAMHANDLER_H
