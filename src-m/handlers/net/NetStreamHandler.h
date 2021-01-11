#ifndef PKTVISORD_NETSTREAMHANDLER_H
#define PKTVISORD_NETSTREAMHANDLER_H

#include "PcapInputStream.h"
#include "StreamHandler.h"
#include <thread>

namespace pktvisor {
namespace handler {

class NetStreamHandler : public pktvisor::StreamHandler
{
    pktvisor::input::PcapInputStream::ConcurrentQueue *_packetQueue;
    std::unique_ptr<std::thread> _thread;

public:
    NetStreamHandler(const std::string &name, std::shared_ptr<pktvisor::input::PcapInputStream> stream);
    virtual ~NetStreamHandler();

    void start() override;
    void stop() override;
};

}
}

#endif //PKTVISORD_NETSTREAMHANDLER_H
