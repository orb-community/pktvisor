#ifndef PKTVISORD_INPUTSTREAM_H
#define PKTVISORD_INPUTSTREAM_H

#include <atomic>
#include <string>
#include <unordered_map>
#include <variant>

namespace pktvisor {

class InputStream
{
protected:
    std::atomic_bool _running = false;
    std::unordered_map<std::string, std::variant<std::string, uint64_t>> _config;

public:
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual ~InputStream(){};

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

#endif //PKTVISORD_INPUTSTREAM_H
