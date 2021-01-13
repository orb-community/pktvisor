#ifndef PKTVISORD_PCAPINPUTMODULEPLUGIN_H
#define PKTVISORD_PCAPINPUTMODULEPLUGIN_H

#include "InputModulePlugin.h"
#include "PcapInputStream.h"
#include <shared_mutex>

namespace pktvisor {
namespace input {

class PcapInputModulePlugin : public pktvisor::InputModulePlugin
{
    // TODO this could be more granular, on names
    std::shared_mutex _mutex;

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

    // CRUD interface, must be thread safe
    void op_create(const std::string &name, const std::string &iface, const std::string &bpf);
    void op_delete(const std::string &name);
};

}
}

#endif //PKTVISORD_PCAPINPUTMODULEPLUGIN_H
