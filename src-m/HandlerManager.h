#ifndef PKTVISORD_HANDLERMANAGER_H
#define PKTVISORD_HANDLERMANAGER_H

#include "StreamHandler.h"
#include <cpp-httplib/httplib.h>

#include <assert.h>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace pktvisor {

/**
 * called from HTTP threads so must be thread safe
 */
class HandlerManager
{
    std::unordered_map<std::string, std::shared_ptr<StreamHandler>> _handlers;
    mutable std::shared_mutex _mutex;

public:
    HandlerManager()
        : _handlers()
    {
    }

    // FIXME thread safety is on the caller
    std::unordered_map<std::string, std::shared_ptr<StreamHandler>> &all_modules()
    {
        return _handlers;
    }

    void add_module(const std::string &name, std::unique_ptr<StreamHandler> &&m)
    {
        assert(!exists(name));
        std::unique_lock lock(_mutex);
        _handlers.emplace(std::make_pair(name, std::move(m)));
    }

    std::shared_ptr<StreamHandler> get_module(const std::string &name)
    {
        assert(exists(name));
        std::shared_lock lock(_mutex);
        return _handlers[name];
    }

    void remove_module(const std::string &name)
    {
        assert(exists(name));
        std::unique_lock lock(_mutex);
        _handlers.erase(name);
    }

    bool exists(const std::string &name) const
    {
        std::shared_lock lock(_mutex);
        return _handlers.count(name) == 1;
    }
};

}

#endif //PKTVISORD_HANDLERMANAGER_H
