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

    virtual ~InputStreamManager()
    {
    }

    // override to atomically ensure we don't remove if there are active consumers
    void remove_module(const std::string &name) override
    {
        std::unique_lock lock(_map_mutex);
        if (_map.count(name) == 0) {
            throw std::runtime_error("module name does not exist");
        }
        if (_map[name]->consumer_count()) {
            throw std::runtime_error("unable to remove, stream has consumers");
        }
        _map[name]->stop();
        _map.erase(name);
    }
};

}

#endif //PKTVISORD_INPUTSTREAMMANAGER_H
