#ifndef PKTVISORD_STREAMHANDLER_H
#define PKTVISORD_STREAMHANDLER_H

#include "AbstractModule.h"

namespace pktvisor {

class StreamHandler : public AbstractModule
{

public:
    StreamHandler(const std::string &name)
        : AbstractModule(name)
    {
    }

    virtual ~StreamHandler(){};
};

}

#endif //PKTVISORD_STREAMHANDLER_H
