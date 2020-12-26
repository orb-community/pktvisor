#ifndef PKTVISORD_INPUTMANAGER_H
#define PKTVISORD_INPUTMANAGER_H

#include "StreamInput.h"
#include <cpp-httplib/httplib.h>

#include <vector>

namespace pktvisor {

class InputManager
{
    std::vector<StreamInput> _inputs;

    void _setup_routes(httplib::Server &svr);

public:
    InputManager(httplib::Server &svr)
    {
        _setup_routes(svr);
    }
};

}

#endif //PKTVISORD_INPUTMANAGER_H
