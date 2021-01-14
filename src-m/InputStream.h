#ifndef PKTVISORD_INPUTSTREAM_H
#define PKTVISORD_INPUTSTREAM_H

#include "AbstractModule.h"
#include "StreamHandler.h"
#include <functional>
#include <shared_mutex>

namespace pktvisor {

class StreamPayload
{
public:
    StreamPayload()
    {
    }
    virtual ~StreamPayload()
    {
    }
};

class InputStream : public AbstractModule
{
public:
    typedef std::function<void(StreamPayload &)> StreamCallback;

protected:
    mutable std::shared_mutex _consumer_mutex;

    std::unordered_map<const StreamHandler *, StreamCallback> _consumers;

public:
    InputStream(const std::string &name)
        : AbstractModule(name)
    {
    }

    virtual ~InputStream(){};

    void register_consumer(const StreamHandler *h, StreamCallback cb)
    {
        std::unique_lock lock(_consumer_mutex);
        _consumers.emplace(std::make_pair(h, std::move(cb)));
    }

    void deregister_consumer(const StreamHandler *h)
    {
        std::unique_lock lock(_consumer_mutex);
        _consumers.erase(h);
    }

    bool has_consumers() const
    {
        std::shared_lock lock(_consumer_mutex);
        return !_consumers.empty();
    }

    auto lock_consumers()
    {
        std::unique_lock lock(_consumer_mutex);
        return lock;
    }
};

}

#endif //PKTVISORD_INPUTSTREAM_H
