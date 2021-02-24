#pragma once

#include "InputModulePlugin.h"
#include "PcapInputStream.h"

namespace vizer::input::pcap {

class PcapInputModulePlugin : public vizer::InputModulePlugin
{

protected:
    void _setup_routes(HttpServer &svr) override;

    void _create(const httplib::Request &req, httplib::Response &res);
    void _read(const httplib::Request &req, httplib::Response &res);
    void _delete(const httplib::Request &req, httplib::Response &res);

public:
    explicit PcapInputModulePlugin(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : vizer::InputModulePlugin{manager, plugin}
    {
    }

    std::string name() const override
    {
        return "PcapInputModulePlugin";
    }
};

}

