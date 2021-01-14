#include "NetStreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <Corrade/Utility/DebugStl.h>

namespace pktvisor {
namespace handler {

NetStreamHandler::NetStreamHandler(const std::string &name, pktvisor::input::PcapInputStream *stream)
    : pktvisor::StreamHandler(name)
    //    , _udpPacketQueue(nullptr)
    , _stream(stream)
{
}

void NetStreamHandler::start()
{
    if (_running) {
        return;
    }
    _running = true;
    !Corrade::Utility::Debug{} << "start";

    _stream->register_consumer(this, [](StreamPayload &p) {
        //        Corrade::Utility::Debug{} << packet.toString();
        auto payload = dynamic_cast<pktvisor::input::PcapStreamPayload &>(p);
        Corrade::Utility::Debug{} << "NET STREAM PACKET\n";
        Corrade::Utility::Debug{} << payload;
    });

    // FIXME async
    //    _udpPacketQueue = stream->register_udp_consumer_async(name, 0);
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

    _stream->deregister_consumer(this);

    if (_thread && _thread->joinable()) {
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