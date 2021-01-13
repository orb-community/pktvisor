#ifndef PKTVISORD_HANDLERMANAGER_H
#define PKTVISORD_HANDLERMANAGER_H

#include "AbstractManager.h"
#include "StreamHandler.h"

namespace pktvisor {

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
};

}

#endif //PKTVISORD_HANDLERMANAGER_H
