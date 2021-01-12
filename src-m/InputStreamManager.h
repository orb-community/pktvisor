#ifndef PKTVISORD_INPUTSTREAMMANAGER_H
#define PKTVISORD_INPUTSTREAMMANAGER_H

#include "InputStream.h"

#include <assert.h>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace pktvisor {

/**
 * called from HTTP threads so must be thread safe
 */
class InputStreamManager
{
    std::unordered_map<std::string, std::shared_ptr<InputStream>> _inputs;
    mutable std::shared_mutex _mutex;

public:
    InputStreamManager()
        : _inputs()
    {
    }

    // FIXME thread safety is on the caller
    std::unordered_map<std::string, std::shared_ptr<InputStream>> &all_modules()
    {
        return _inputs;
    }

    void add_module(const std::string &name, std::unique_ptr<InputStream> &&m)
    {
        assert(!exists(name));
        std::unique_lock lock(_mutex);
        _inputs.emplace(std::make_pair(name, std::move(m)));
    }

    std::shared_ptr<InputStream> get_module(const std::string &name)
    {
        assert(exists(name));
        std::shared_lock lock(_mutex);
        return _inputs[name];
    }

    void remove_module(const std::string &name)
    {
        assert(exists(name));
        std::unique_lock lock(_mutex);
        _inputs.erase(name);
    }

    bool exists(const std::string &name) const
    {
        std::shared_lock lock(_mutex);
        return _inputs.count(name) == 1;
    }
};

}

#endif //PKTVISORD_INPUTSTREAMMANAGER_H
