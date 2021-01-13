#ifndef PKTVISORD_INPUTSTREAMMANAGER_H
#define PKTVISORD_INPUTSTREAMMANAGER_H

#include "AbstractManager.h"
#include "InputStream.h"

namespace pktvisor {

/**
 * called from HTTP threads so must be thread safe
 */
class InputStreamManager : public AbstractManager<InputStream>
{

public:
    InputStreamManager()
        : AbstractManager<InputStream>()
    {
    }
};

}

#endif //PKTVISORD_INPUTSTREAMMANAGER_H
