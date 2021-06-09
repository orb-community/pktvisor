/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "NetHandlerModulePlugin.h"
#include "CoreRegistry.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "NetStreamHandler.h"
#include <Corrade/PluginManager/AbstractManager.h>
#include <nlohmann/json.hpp>

CORRADE_PLUGIN_REGISTER(VisorHandlerNet, visor::handler::net::NetHandlerModulePlugin,
    "visor.module.handler/1.0")

namespace visor::handler::net {

using namespace visor::input::pcap;
using json = nlohmann::json;

void NetHandlerModulePlugin::setup_routes(HttpServer *svr)
{
    svr->Get("/api/v1/inputs/pcap/(\\w+)/handlers/net/(\\w+)", [this](const httplib::Request &req, httplib::Response &res) {
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
            auto net_handler = dynamic_cast<NetStreamHandler *>(handler);
            if (!net_handler) {
                res.status = 400;
                result["error"] = "handler stream is not net";
                res.set_content(result.dump(), "text/json");
                return;
            }
            net_handler->info_json(result);
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result.clear();
            result["error"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });
    svr->Get("/api/v1/inputs/pcap/(\\w+)/handlers/net/(\\w+)/bucket/(\\d+)", [this](const httplib::Request &req, httplib::Response &res) {
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
            auto net_handler = dynamic_cast<NetStreamHandler *>(handler);
            if (!net_handler) {
                res.status = 400;
                result["error"] = "handler stream is not net";
                res.set_content(result.dump(), "text/json");
                return;
            }
            net_handler->window_json(result, std::stoi(req.matches[3]), false);
            res.set_content(result.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            result.clear();
            result["error"] = e.what();
            res.set_content(result.dump(), "text/json");
        }
    });
}
std::unique_ptr<StreamHandler> NetHandlerModulePlugin::instantiate(const std::string &name, InputStream *input_stream, const Configurable *config)
{
    // TODO using config as both window config and module config
    auto handler_module = std::make_unique<NetStreamHandler>(name, input_stream, config);
    handler_module->config_merge(*config);
    return handler_module;
}

}