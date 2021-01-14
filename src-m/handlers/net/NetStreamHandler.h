#ifndef PKTVISORD_NETSTREAMHANDLER_H
#define PKTVISORD_NETSTREAMHANDLER_H

#include "PcapInputStream.h"
#include "StreamHandler.h"
#include <thread>

namespace pktvisor {
namespace handler {

class NetStreamHandler : public pktvisor::StreamHandler
{

    //    pktvisor::input::PcapInputStream::ConcurrentUdpQueue *_udpPacketQueue;

    std::unique_ptr<std::thread> _thread;
    pktvisor::input::PcapInputStream *_stream;

    sigslot::connection _udp_connection;

public:
    NetStreamHandler(const std::string &name, pktvisor::input::PcapInputStream *stream);
    virtual ~NetStreamHandler();

    void start() override;
    void stop() override;
};

}
}

#endif //PKTVISORD_NETSTREAMHANDLER_H
