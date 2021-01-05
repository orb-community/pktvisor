#ifndef PKTVISORD_PCAPSTREAMINPUTDESC_H
#define PKTVISORD_PCAPSTREAMINPUTDESC_H

#include "InputModuleDesc.h"

namespace pktvisor {
namespace input {

class PcapStreamInputDesc : public pktvisor::InputModuleDesc
{
protected:
    void _setup_routes(httplib::Server &svr) override;

public:
    explicit PcapStreamInputDesc(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : pktvisor::InputModuleDesc{manager, plugin}
    {
    }

    std::string name() const override
    {
        return "PcapStreamInputDesc";
    }
};

}
}

#endif //PKTVISORD_PCAPSTREAMINPUTDESC_H
