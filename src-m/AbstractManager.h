#ifndef PKTVISORD_ABSTRACTMANAGER_H
#define PKTVISORD_ABSTRACTMANAGER_H

#include "AbstractModule.h"
#include <assert.h>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace pktvisor {

/**
 * called from HTTP threads so must be thread safe
 */
template <typename ModuleType>
class AbstractManager
{
    static_assert(std::is_base_of<AbstractModule, ModuleType>::value, "ModuleType must inherit from AbstractModule");

protected:
    typedef std::unordered_map<std::string, std::unique_ptr<ModuleType>> ModuleMap;
    ModuleMap _map;
    mutable std::shared_mutex _map_mutex;

public:
    AbstractManager()
        : _map()
    {
    }

    auto all_modules()
    {
        struct retVals {
            ModuleMap &map;
            std::unique_lock<std::shared_mutex> lock;
        };
        std::unique_lock lock(_map_mutex);
        return retVals{_map, std::move(lock)};
    }

    // atomically ensure module starts before arriving in registry
    virtual void add_module(const std::string &name, std::unique_ptr<ModuleType> &&m)
    {
        std::unique_lock lock(_map_mutex);
        if (_map.count(name)) {
            throw std::runtime_error("module name already exists");
        }
        m->start();
        _map.emplace(std::make_pair(name, std::move(m)));
    }

    // note the module returned has separate thread safety, but the returned lock ensures
    // the module will not be removed before the caller has a chance to initialize
    auto get_module(const std::string &name)
    {
        std::unique_lock lock(_map_mutex);
        if (_map.count(name) == 0) {
            throw std::runtime_error("module name does not exist");
        }
        struct retVals {
            ModuleType *map;
            std::unique_lock<std::shared_mutex> lock;
        };
        return retVals{_map[name].get(), std::move(lock)};
    }

    virtual void remove_module(const std::string &name)
    {
        std::unique_lock lock(_map_mutex);
        if (_map.count(name) == 0) {
            throw std::runtime_error("module name does not exist");
        }
        _map[name]->stop();
        _map.erase(name);
    }

    // note, this only guarantees the name existed at the time of call, watch for race conditions!
    bool exists(const std::string &name) const
    {
        std::shared_lock lock(_map_mutex);
        return _map.count(name) == 1;
    }
};

}

#endif //PKTVISORD_ABSTRACTMANAGER_H
