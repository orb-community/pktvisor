#ifndef PKTVISORD_NETSTREAMHANDLER_H
#define PKTVISORD_NETSTREAMHANDLER_H

#include "PcapInputStream.h"
#include "StreamHandler.h"

namespace pktvisor {
namespace handler {

class NetStreamHandler : public pktvisor::StreamHandler
{
public:
    NetStreamHandler(std::shared_ptr<pktvisor::input::PcapInputStream> stream);

    void start() override;
    void stop() override;
};

}
}

#endif //PKTVISORD_NETSTREAMHANDLER_H
