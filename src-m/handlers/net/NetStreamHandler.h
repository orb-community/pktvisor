#ifndef PKTVISORD_NETSTREAMHANDLER_H
#define PKTVISORD_NETSTREAMHANDLER_H

#include "PcapInputStream.h"
#include "StreamHandler.h"
#include <thread>

namespace pktvisor {
namespace handler {

class NetStreamHandler : public pktvisor::StreamHandler
{

    pktvisor::input::PcapInputStream *_stream;

    sigslot::connection _pkt_connection;

    void process_packet(pcpp::Packet &payload);

public:
    NetStreamHandler(const std::string &name, pktvisor::input::PcapInputStream *stream);
    virtual ~NetStreamHandler();

    void start() override;
    void stop() override;
};

}
}

#endif //PKTVISORD_NETSTREAMHANDLER_H
