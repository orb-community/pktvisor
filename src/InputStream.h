#pragma once

#include "AbstractModule.h"
#include "StreamHandler.h"

namespace vizer {

class InputStream : public AbstractModule
{

public:
    InputStream(const std::string &name)
        : AbstractModule(name)
    {
    }

    virtual ~InputStream(){};

    virtual size_t consumer_count() = 0;
};

}

