#include "NetHandlerModulePlugin.h"
#include <Corrade/PluginManager/AbstractManager.h>
#include <json/json.hpp>

using json = nlohmann::json;

CORRADE_PLUGIN_REGISTER(NetHandler, pktvisor::handler::NetHandlerModulePlugin,
    "com.ns1.module.handler/1.0")

namespace pktvisor {
namespace handler {

void NetHandlerModulePlugin::_setup_routes(HttpServer &svr)
{
    // CREATE
    svr.Post("/api/v1/inputs/pcap/(\\w+)/handlers/net", [this](const httplib::Request &req, httplib::Response &res) {
        json result;
        try {
            auto body = json::parse(req.body);
            std::unordered_map<std::string, std::string> schema = {
                {"name", "\\w+"}};
            try {
                _check_schema(body, schema);
            } catch (const SchemaException &e) {
                res.status = 400;
                result["error"] = e.what();
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto input_name = req.matches[1];
            if (!_input_manager->exists(input_name)) {
                res.status = 404;
                result["error"] = "input name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            if (_handler_manager->exists(body["name"])) {
                res.status = 400;
                result["error"] = "handler name already exists";
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto input_module = _input_manager->get_module(input_name);
            auto pcap_stream = std::dynamic_pointer_cast<pktvisor::input::PcapInputStream>(input_module);
            if (!pcap_stream) {
                res.status = 400;
                result["error"] = "input stream is not pcap";
                res.set_content(result.dump(), "text/json");
                return;
            }
            if (!input_module->running()) {
                res.status = 400;
                result["error"] = "input stream is not running";
                res.set_content(result.dump(), "text/json");
                return;
            }
            op_create(pcap_stream, body["name"]);
            result["name"] = body["name"];
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result["error"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });
}

const NetStreamHandler *NetHandlerModulePlugin::op_create(std::shared_ptr<pktvisor::input::PcapInputStream> stream, const std::string &name)
{
    auto handler_module = std::make_unique<NetStreamHandler>(name, stream);
    //    handler_module->set_config("iface", iface);
    handler_module->start();
    _handler_manager->add_module(name, std::move(handler_module));
    return handler_module.get();
}

}
}