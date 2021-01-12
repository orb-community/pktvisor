#include "NetStreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <Corrade/Utility/DebugStl.h>

namespace pktvisor {
namespace handler {

NetStreamHandler::NetStreamHandler(const std::string &name, std::shared_ptr<pktvisor::input::PcapInputStream> stream)
    : pktvisor::StreamHandler(name)
    , _udpPacketQueue(nullptr)
{
    //    _udpPacketQueue = stream->register_udp_consumer_async(name, 0);
    stream->register_udp_consumer(name, 0, [](pcpp::UdpLayer &udp) {
        Corrade::Utility::Debug{} << udp.toString();
    });
}

void NetStreamHandler::start()
{
    if (_running) {
        return;
    }
    _running = true;
    !Corrade::Utility::Debug{} << "start";

    // FIXME async
    /*
    _thread = std::make_unique<std::thread>([this]() {
        std::shared_ptr<pcpp::UdpLayer> item;
        while (_running) {
            if (_udpPacketQueue->wait_dequeue_timed(item, std::chrono::milliseconds(5))) {
                Corrade::Utility::Debug{} << item->toString();
            }
        }
    });
     */
}

void NetStreamHandler::stop()
{
    if (!_running) {
        return;
    }
    !Corrade::Utility::Debug{} << "stop";
    _running = false;

    if (_thread->joinable()) {
        _thread->join();
    }
}

NetStreamHandler::~NetStreamHandler()
{
    if (_running)
        stop();
}

}
}