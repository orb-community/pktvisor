#ifndef VIZERD_INPUTSTREAM_H
#define VIZERD_INPUTSTREAM_H

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

#endif //VIZERD_INPUTSTREAM_H
