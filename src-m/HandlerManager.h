#ifndef PKTVISORD_HANDLERMANAGER_H
#define PKTVISORD_HANDLERMANAGER_H

#include "StreamHandler.h"
#include <cpp-httplib/httplib.h>

#include <assert.h>
#include <string>
#include <unordered_map>

namespace pktvisor {

class HandlerManager
{
    std::unordered_map<std::string, std::shared_ptr<StreamHandler>> _handlers;

public:
    HandlerManager()
        : _handlers()
    {
    }

    std::unordered_map<std::string, std::shared_ptr<StreamHandler>> &all_modules()
    {
        return _handlers;
    }

    void add_module(const std::string &name, std::unique_ptr<StreamHandler> &&m)
    {
        assert(!exists(name));
        _handlers.emplace(std::make_pair(name, std::move(m)));
    }

    std::shared_ptr<StreamHandler> get_module(const std::string &name)
    {
        assert(exists(name));
        return _handlers[name];
    }

    void remove_module(const std::string &name)
    {
        assert(exists(name));
        _handlers.erase(name);
    }

    bool exists(const std::string &name) const
    {
        return _handlers.count(name) == 1;
    }
};

}

#endif //PKTVISORD_HANDLERMANAGER_H
