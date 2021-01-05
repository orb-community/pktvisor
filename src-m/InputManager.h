#ifndef PKTVISORD_INPUTMANAGER_H
#define PKTVISORD_INPUTMANAGER_H

#include "StreamInput.h"
#include <cpp-httplib/httplib.h>

#include <vector>

namespace pktvisor {

class InputManager
{
    std::vector<std::unique_ptr<StreamInput>> _inputs;

public:
    InputManager()
        : _inputs()
    {
    }

    void add_module(std::unique_ptr<StreamInput> &&m)
    {
        _inputs.emplace_back(std::move(m));
    }
};

}

#endif //PKTVISORD_INPUTMANAGER_H
