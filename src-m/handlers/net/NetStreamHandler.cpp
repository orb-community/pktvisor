#include "NetStreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <Corrade/Utility/DebugStl.h>

namespace pktvisor {
namespace handler {

NetStreamHandler::NetStreamHandler(const std::string &name, std::shared_ptr<pktvisor::input::PcapInputStream> stream)
    : pktvisor::StreamHandler(name)
    , _packetQueue(nullptr)
{
    _packetQueue = stream->register_consumer(name);
}

void NetStreamHandler::start()
{
    if (_running) {
        return;
    }
    _running = true;
    !Corrade::Utility::Debug{} << "start";
    _thread = std::make_unique<std::thread>([this]() {
        while (_running) {
            std::shared_ptr<pcpp::Packet> item;
            _packetQueue->wait_dequeue_timed(item, std::chrono::milliseconds(5));
            if (item) {
                std::vector<std::string> result;
                item->toStringList(result);
                Corrade::Utility::Debug{} << result;
            }
        }
    });
}

void NetStreamHandler::stop()
{
    if (!_running) {
        return;
    }
    !Corrade::Utility::Debug{} << "stop";
    _running = false;
    _thread->join();
}

NetStreamHandler::~NetStreamHandler()
{
    if (_running)
        stop();
}

}
}