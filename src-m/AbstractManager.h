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

    auto module_get_all_locked()
    {
        struct retVals {
            ModuleMap &map;
            std::unique_lock<std::shared_mutex> lock;
        };
        std::unique_lock lock(_map_mutex);
        return retVals{_map, std::move(lock)};
    }

    // atomically ensure module starts before arriving in registry, if requested
    virtual void module_add(std::unique_ptr<ModuleType> &&m, bool start = true)
    {
        std::unique_lock lock(_map_mutex);
        if (_map.count(m->name())) {
            throw std::runtime_error("module name already exists");
        }
        if (start) {
            m->start();
        }
        _map.emplace(m->name(), std::move(m));
    }

    // note the module returned has separate thread safety, but the returned lock ensures
    // the module will not be removed before the caller has a chance to initialize
    auto module_get_locked(const std::string &name)
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

    virtual void module_remove(const std::string &name)
    {
        std::unique_lock lock(_map_mutex);
        if (_map.count(name) == 0) {
            throw std::runtime_error("module name does not exist");
        }
        _map[name]->stop();
        _map.erase(name);
    }

    // note, this only guarantees the name existed at the time of call, watch for race conditions!
    bool module_exists(const std::string &name) const
    {
        std::shared_lock lock(_map_mutex);
        return _map.count(name) == 1;
    }
};

}

#endif //PKTVISORD_ABSTRACTMANAGER_H
