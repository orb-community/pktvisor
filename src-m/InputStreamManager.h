#ifndef PKTVISORD_INPUTSTREAMMANAGER_H
#define PKTVISORD_INPUTSTREAMMANAGER_H

#include "InputStream.h"
#include <cpp-httplib/httplib.h>

#include <assert.h>
#include <string>
#include <unordered_map>

namespace pktvisor {

class InputStreamManager
{
    std::unordered_map<std::string, std::shared_ptr<InputStream>> _inputs;

public:
    InputStreamManager()
        : _inputs()
    {
    }

    void add_module(const std::string &name, std::unique_ptr<InputStream> &&m)
    {
        assert(!exists(name));
        _inputs.emplace(std::make_pair(name, std::move(m)));
    }

    std::shared_ptr<InputStream> get_module(const std::string &name)
    {
        assert(exists(name));
        return _inputs[name];
    }

    bool exists(const std::string &name) const
    {
        return _inputs.count(name) == 1;
    }
};

}

#endif //PKTVISORD_INPUTSTREAMMANAGER_H
