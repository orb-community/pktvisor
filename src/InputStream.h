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

    // TODO this should be const, currently limited by slot architecture
    virtual size_t consumer_count() = 0;

    void _common_info_json(json &j) const
    {
        AbstractModule::_common_info_json(j);
        // TODO const correctness on consumer count
        j["input"]["consumers"] = const_cast<InputStream *>(this)->consumer_count();
    }
};

}

