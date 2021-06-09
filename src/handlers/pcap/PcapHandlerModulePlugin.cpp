/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "PcapHandlerModulePlugin.h"
#include "CoreRegistry.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "PcapInputStream.h"
#include "PcapStreamHandler.h"
#include <Corrade/PluginManager/AbstractManager.h>
#include <nlohmann/json.hpp>

CORRADE_PLUGIN_REGISTER(VisorHandlerPcap, visor::handler::pcap::PcapHandlerModulePlugin,
    "dev.visor.module.handler/1.0")

namespace visor::handler::pcap {

using namespace visor::input::pcap;
using json = nlohmann::json;

void PcapHandlerModulePlugin::setup_routes(HttpServer *svr)
{
    // CREATE
    /*
    svr->Post("/api/v1/inputs/pcap/(\\w+)/handlers/pcap", [this](const httplib::Request &req, httplib::Response &res) {
        json result;
        try {
            auto body = json::parse(req.body);
            SchemaMap req_schema = {{"name", "\\w+"}};
            SchemaMap opt_schema = {{"periods", "\\d{1,3}"}, {"deep_sample_rate", "\\d{1,3}"}};
            try {
                check_schema(body, req_schema, opt_schema);
            } catch (const SchemaException &e) {
                res.status = 400;
                result["error"] = e.what();
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto input_name = req.matches[1];
            if (!registry()->input_manager()->module_exists(input_name)) {
                res.status = 404;
                result["error"] = "input name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            if (registry()->handler_manager()->module_exists(body["name"])) {
                res.status = 400;
                result["error"] = "handler name already exists";
                res.set_content(result.dump(), "text/json");
                return;
            }
            // note, may be a race on exists() above, this may fail. if so we will catch and 500.
            auto [input_stream, stream_mgr_lock] = registry()->input_manager()->module_get_locked(input_name);
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
            auto handler_module = std::make_unique<PcapStreamHandler>(body["name"], pcap_stream, periods, deep_sample_rate);
            registry()->handler_manager()->module_add(std::move(handler_module));
            result["name"] = body["name"];
            result["periods"] = periods;
            result["deep_sample_rate"] = deep_sample_rate;
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result.clear();
            result["error"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });
     */
    svr->Get("/api/v1/inputs/pcap/(\\w+)/handlers/pcap/(\\w+)", [this](const httplib::Request &req, httplib::Response &res) {
        json result;
        try {
            auto input_name = req.matches[1];
            if (!registry()->input_manager()->module_exists(input_name)) {
                res.status = 404;
                result["error"] = "input name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto handler_name = req.matches[2];
            if (!registry()->handler_manager()->module_exists(handler_name)) {
                res.status = 404;
                result["error"] = "handler name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto [handler, handler_mgr_lock] = registry()->handler_manager()->module_get_locked(handler_name);
            auto pcap_handler = dynamic_cast<PcapStreamHandler *>(handler);
            if (!pcap_handler) {
                res.status = 400;
                result["error"] = "handler stream is not pcap";
                res.set_content(result.dump(), "text/json");
                return;
            }
            pcap_handler->info_json(result);
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result.clear();
            result["error"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });
    svr->Get("/api/v1/inputs/pcap/(\\w+)/handlers/pcap/(\\w+)/bucket/(\\d+)", [this](const httplib::Request &req, httplib::Response &res) {
        json result;
        try {
            auto input_name = req.matches[1];
            if (!registry()->input_manager()->module_exists(input_name)) {
                res.status = 404;
                result["error"] = "input name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto handler_name = req.matches[2];
            if (!registry()->handler_manager()->module_exists(handler_name)) {
                res.status = 404;
                result["error"] = "handler name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto [handler, handler_mgr_lock] = registry()->handler_manager()->module_get_locked(handler_name);
            auto pcap_handler = dynamic_cast<PcapStreamHandler *>(handler);
            if (!pcap_handler) {
                res.status = 400;
                result["error"] = "handler stream is not pcap";
                res.set_content(result.dump(), "text/json");
                return;
            }
            pcap_handler->window_json(result, std::stoi(req.matches[3]), false);
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result.clear();
            result["error"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });
    // DELETE
    /*
    svr->Delete("/api/v1/inputs/pcap/(\\w+)/handlers/pcap/(\\w+)", [this](const httplib::Request &req, httplib::Response &res) {
        json result;
        try {
            auto input_name = req.matches[1];
            if (!registry()->input_manager()->module_exists(input_name)) {
                res.status = 404;
                result["error"] = "input name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            auto handler_name = req.matches[2];
            if (!registry()->handler_manager()->module_exists(handler_name)) {
                res.status = 404;
                result["error"] = "handler name does not exist";
                res.set_content(result.dump(), "text/json");
                return;
            }
            registry()->handler_manager()->module_remove(handler_name);
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result.clear();
            result["error"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });
     */
}
std::unique_ptr<StreamHandler> PcapHandlerModulePlugin::instantiate(const std::string &name, InputStream *input_stream, const Configurable *config)
{
    // TODO using config as both window config and module config
    auto handler_module = std::make_unique<PcapStreamHandler>(name, input_stream, config);
    return handler_module;
}

}