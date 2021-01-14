#include "NetStreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <Corrade/Utility/DebugStl.h>

namespace pktvisor {
namespace handler {

NetStreamHandler::NetStreamHandler(const std::string &name, pktvisor::input::PcapInputStream *stream)
    : pktvisor::StreamHandler(name)
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

    _pkt_connection = _stream->packet_signal.connect(&NetStreamHandler::process_packet, this);
}

void NetStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    !Corrade::Utility::Debug{} << "stop";
    _running = false;

    _pkt_connection.disconnect();
}

NetStreamHandler::~NetStreamHandler()
{
    !Corrade::Utility::Debug{} << "destroy";
}

void NetStreamHandler::process_packet(pcpp::Packet &payload)
{
    Corrade::Utility::Debug{} << _name << ":" << payload.toString();
}

}
}