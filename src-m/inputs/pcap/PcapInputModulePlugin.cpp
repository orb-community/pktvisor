#include "PcapInputModulePlugin.h"
#include "PcapInputStream.h"
#include <Corrade/PluginManager/AbstractManager.h>
#include <json/json.hpp>

using json = nlohmann::json;

CORRADE_PLUGIN_REGISTER(PcapInput, pktvisor::input::PcapInputModulePlugin,
    "com.ns1.module.input/1.0")

namespace pktvisor {
namespace input {

void PcapInputModulePlugin::_setup_routes(httplib::Server &svr)
{

    // CREATE
    svr.Post("/api/v1/inputs/pcap", [this](const httplib::Request &req, httplib::Response &res) {
        json error, result;
        try {
            auto body = json::parse(req.body);
            if (!body.contains("name")) {
                res.status = 400;
                error["error"] = "name is required";
                res.set_content(error.dump(), "text/json");
            }
            if (!body.contains("iface")) {
                res.status = 400;
                error["error"] = "iface is required";
                res.set_content(error.dump(), "text/json");
            }
            if (_input_manager->exists(body["name"])) {
                res.status = 400;
                error["error"] = "name already exists";
                res.set_content(error.dump(), "text/json");
            }
            // TODO configure the module with data from post body
            auto input_module = op_create(body["name"], body["iface"]);

            result["name"] = body["name"];
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            error["error"] = e.what();
            res.set_content(error.dump(), "text/json");
        }
    });

    // DELETE
    svr.Post(R"(^/api/v1/inputs/pcap/(\w+))", [this](const httplib::Request &req, httplib::Response &res) {
        json error, result;
        try {
            if (!_input_manager->exists(req.matches[1])) {
                res.status = 404;
                error["error"] = "name does not exist";
                res.set_content(error.dump(), "text/json");
            }
            op_delete(req.matches[1]);
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            error["error"] = e.what();
            res.set_content(error.dump(), "text/json");
        }
    });
}
const pktvisor::InputStream *PcapInputModulePlugin::op_create(const std::string &name, const std::string &iface)
{
    auto input_module = std::make_unique<PcapInputStream>();
    input_module->set_config("iface", iface);
    input_module->start();
    _input_manager->add_module(name, std::move(input_module));
    return input_module.get();
}

void PcapInputModulePlugin::op_delete(const std::string &name)
{
    auto input_module = _input_manager->get_module(name);
    input_module->stop();
}

}
}