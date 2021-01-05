#ifndef PKTVISORD_PCAPSTREAMINPUT_H
#define PKTVISORD_PCAPSTREAMINPUT_H

#include "InputModuleDesc.h"

namespace pktvisor {
namespace input {
namespace pcap {

class PcapStreamInput : public pktvisor::InputModuleDesc
{
protected:
    void _setup_routes(httplib::Server &svr) override;

public:
    explicit PcapStreamInput(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : pktvisor::InputModuleDesc{manager, plugin}
    {
    }

    std::string name() const override
    {
        return "PcapStreamInput";
    }
};

}
}
}

#endif //PKTVISORD_PCAPSTREAMINPUT_H
