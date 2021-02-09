#ifndef VIZERD_HANDLERMANAGER_H
#define VIZERD_HANDLERMANAGER_H

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

#endif //VIZERD_HANDLERMANAGER_H
