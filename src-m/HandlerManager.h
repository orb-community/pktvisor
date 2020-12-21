#ifndef PKTVISORD_HANDLERMANAGER_H
#define PKTVISORD_HANDLERMANAGER_H

#include "StreamHandler.h"
#include <cpp-httplib/httplib.h>

#include <vector>

namespace pktvisor {

class HandlerManager
{
    std::vector<StreamHandler> _handlers;

public:
    HandlerManager(httplib::Server &svr)
    {
    }
};

}

#endif //PKTVISORD_HANDLERMANAGER_H
