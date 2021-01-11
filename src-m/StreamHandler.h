#ifndef PKTVISORD_STREAMHANDLER_H
#define PKTVISORD_STREAMHANDLER_H

#include <atomic>
#include <string>
#include <unordered_map>
#include <variant>

namespace pktvisor {

class StreamHandler
{
protected:
    std::atomic_bool _running = false;
    std::string _name;
    std::unordered_map<std::string, std::variant<std::string, uint64_t>> _config;

public:
    StreamHandler(const std::string &name)
        : _name(name)
    {
    }
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual ~StreamHandler(){};

    const std::string &name() const
    {
        return _name;
    }

    bool running() const
    {
        return _running;
    }

    template <class T>
    void set_config(const std::string &key, const T &val)
    {
        _config[key] = val;
    }
};
}

#endif //PKTVISORD_STREAMHANDLER_H
