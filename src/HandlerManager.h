#pragma once

#include "AbstractManager.h"
#include "StreamHandler.h"

namespace vizer {

/**
 * called from HTTP threads so must be thread safe
 */
class HandlerManager : public AbstractManager<StreamHandler>
{

public:
    HandlerManager()
        : AbstractManager<StreamHandler>()
    {
    }

    virtual ~HandlerManager()
    {
    }
};

}

