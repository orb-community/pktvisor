#ifndef PKTVISORD_PCAPINPUTMODULEPLUGIN_H
#define PKTVISORD_PCAPINPUTMODULEPLUGIN_H

#include "InputModulePlugin.h"
#include "PcapInputStream.h"

namespace pktvisor {
namespace input {

class PcapInputModulePlugin : public pktvisor::InputModulePlugin
{
protected:
    void _setup_routes(HttpServer &svr) override;

public:
    explicit PcapInputModulePlugin(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : pktvisor::InputModulePlugin{manager, plugin}
    {
    }

    std::string name() const override
    {
        return "PcapInputModulePlugin";
    }

    // CRUD interface
    const PcapInputStream *op_create(const std::string &name, const std::string &iface);
    void op_delete(const std::string &name);
};

}
}

#endif //PKTVISORD_PCAPINPUTMODULEPLUGIN_H
