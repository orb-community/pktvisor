#ifndef PKTVISORD_ABSTRACTMANAGER_H
#define PKTVISORD_ABSTRACTMANAGER_H

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
public:
    typedef std::unordered_map<std::string, std::shared_ptr<ModuleType>> ModuleMap;
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

    void add_module(const std::string &name, std::unique_ptr<ModuleType> &&m)
    {
        assert(!exists(name));
        std::unique_lock lock(_map_mutex);
        _map.emplace(std::make_pair(name, std::move(m)));
    }

    // note the module returned has separate thread safety
    std::shared_ptr<ModuleType> get_module(const std::string &name)
    {
        assert(exists(name));
        std::unique_lock lock(_map_mutex);
        return _map[name];
    }

    void remove_module(const std::string &name)
    {
        assert(exists(name));
        std::unique_lock lock(_map_mutex);
        _map.erase(name);
    }

    // note, this does not guarantee the item will still be there for a subsequent add/remove call!
    bool exists(const std::string &name) const
    {
        std::shared_lock lock(_map_mutex);
        return _map.count(name) == 1;
    }
};

}

#endif //PKTVISORD_ABSTRACTMANAGER_H
