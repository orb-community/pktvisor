#include "NetHandlerModulePlugin.h"
#include "NetStreamHandler.h"
#include "PcapInputStream.h"
#include <Corrade/PluginManager/AbstractManager.h>
#include <json/json.hpp>

CORRADE_PLUGIN_REGISTER(NetHandler, pktvisor::handler::net::NetHandlerModulePlugin,
    "com.ns1.module.handler/1.0")

namespace pktvisor::handler::net {

using namespace pktvisor::input::pcap;
using json = nlohmann::json;

void NetHandlerModulePlugin::_setup_routes(HttpServer &svr)
{
    // CREATE
    svr.Post("/api/v1/inputs/pcap/(\\w+)/handlers/net", [this](const httplib::Request &req, httplib::Response &res) {
        json result;
        try {
            auto body = json::parse(req.body);
            SchemaMap req_schema = {{"name", "\\w+"}};
            SchemaMap opt_schema = {{"periods", "\\d{1,3}"}, {"deep_sample_rate", "\\d{1,3}"}};
            try {
                _check_schema(body, req_schema, opt_schema);
            } catch (const SchemaException &e) {
                res.status = 400;
                result["error"] = e.what();
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto input_name = req.matches[1];
            if (!_input_manager->module_exists(input_name)) {
                res.status = 404;
                result["error"] = "input name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            if (_handler_manager->module_exists(body["name"])) {
                res.status = 400;
                result["error"] = "handler name already exists";
                res.set_content(result.dump(), "text/json");
                return;
            }
            // note, may be a race on exists() above, this may fail. if so we will catch and 500.
            auto [input_stream, stream_mgr_lock] = _input_manager->module_get_locked(input_name);
            assert(input_stream);
            auto pcap_stream = dynamic_cast<PcapInputStream *>(input_stream);
            if (!pcap_stream) {
                res.status = 400;
                result["error"] = "input stream is not pcap";
                res.set_content(result.dump(), "text/json");
                return;
            }
            if (!input_stream->running()) {
                res.status = 400;
                result["error"] = "input stream is not running";
                res.set_content(result.dump(), "text/json");
                return;
            }
            // TODO use global default from command line
            uint periods{5};
            uint deep_sample_rate{100};
            if (body.contains("periods")) {
                periods = body["periods"];
            }
            if (body.contains("deep_sample_rate")) {
                deep_sample_rate = body["deep_sample_rate"];
            }
            auto handler_module = std::make_unique<NetStreamHandler>(body["name"], pcap_stream, periods, deep_sample_rate);
            _handler_manager->module_add(std::move(handler_module));
            result["name"] = body["name"];
            result["periods"] = periods;
            result["deep_sample_rate"] = deep_sample_rate;
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result["error"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });
    svr.Get("/api/v1/inputs/pcap/(\\w+)/handlers/net/(\\w+)", [this](const httplib::Request &req, httplib::Response &res) {
        json result;
        try {
            auto input_name = req.matches[1];
            if (!_input_manager->module_exists(input_name)) {
                res.status = 404;
                result["result"] = "input name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto handler_name = req.matches[2];
            if (!_handler_manager->module_exists(handler_name)) {
                res.status = 404;
                result["result"] = "handler name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto [handler, handler_mgr_lock] = _handler_manager->module_get_locked(handler_name);
            auto net_handler = dynamic_cast<NetStreamHandler *>(handler);
            if (!net_handler) {
                res.status = 400;
                result["error"] = "handler stream is not net";
                res.set_content(result.dump(), "text/json");
                return;
            }
            result = net_handler->info_json();
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result["result"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });
    svr.Get("/api/v1/inputs/pcap/(\\w+)/handlers/net/(\\w+)/bucket/(\\d+)", [this](const httplib::Request &req, httplib::Response &res) {
        json result;
        try {
            auto input_name = req.matches[1];
            if (!_input_manager->module_exists(input_name)) {
                res.status = 404;
                result["result"] = "input name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto handler_name = req.matches[2];
            if (!_handler_manager->module_exists(handler_name)) {
                res.status = 404;
                result["result"] = "handler name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto [handler, handler_mgr_lock] = _handler_manager->module_get_locked(handler_name);
            auto net_handler = dynamic_cast<NetStreamHandler *>(handler);
            if (!net_handler) {
                res.status = 400;
                result["error"] = "handler stream is not net";
                res.set_content(result.dump(), "text/json");
                return;
            }
            net_handler->to_json(result, std::stoi(req.matches[3]), false);
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result["result"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });
    // DELETE
    svr.Delete("/api/v1/inputs/pcap/(\\w+)/handlers/net/(\\w+)", [this](const httplib::Request &req, httplib::Response &res) {
        json result;
        try {
            auto input_name = req.matches[1];
            if (!_input_manager->module_exists(input_name)) {
                res.status = 404;
                result["result"] = "input name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto handler_name = req.matches[2];
            if (!_handler_manager->module_exists(handler_name)) {
                res.status = 404;
                result["result"] = "handler name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            _handler_manager->module_remove(handler_name);
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result["result"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });
}

}