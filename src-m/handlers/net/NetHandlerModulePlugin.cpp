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
            // note, may be a race on exists() above, this may fail. if so we will catch and 500.
            auto input_module = _input_manager->get_module(input_name);
            assert(input_module);
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
            op_create(input_name, body["name"]);
            result["name"] = body["name"];
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result["error"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });
    // DELETE
    svr.Delete("/api/v1/inputs/pcap/(\\w+)/handlers/net/(\\w+)", [this](const httplib::Request &req, httplib::Response &res) {
        json result;
        try {
            auto input_name = req.matches[1];
            if (!_input_manager->exists(input_name)) {
                res.status = 404;
                result["result"] = "input name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto handler_name = req.matches[2];
            if (!_handler_manager->exists(handler_name)) {
                res.status = 404;
                result["result"] = "handler name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            // races will fail with 500
            op_delete(handler_name);
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result["result"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });
}

void NetHandlerModulePlugin::op_create(const std::string &input_name, const std::string &handler_name)
{
    std::unique_lock lock(_mutex);
    auto stream = _input_manager->get_module(input_name);
    assert(stream);
    auto pcap_stream = std::dynamic_pointer_cast<pktvisor::input::PcapInputStream>(stream);
    assert(pcap_stream);
    auto handler_module = std::make_unique<NetStreamHandler>(handler_name, pcap_stream);
    //    handler_module->set_config("iface", iface);
    handler_module->start();
    _handler_manager->add_module(handler_name, std::move(handler_module));
}

void NetHandlerModulePlugin::op_delete(const std::string &handler_name)
{
    std::unique_lock lock(_mutex);
    auto handler = _handler_manager->get_module(handler_name);
    assert(handler);
    auto net_handler = std::dynamic_pointer_cast<NetStreamHandler>(handler);
    assert(net_handler);
    net_handler->stop();
    _handler_manager->remove_module(handler_name);
}

}
}