/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "PcapInputModulePlugin.h"
#include "CoreRegistry.h"
#include "InputStreamManager.h"
#include <Corrade/PluginManager/AbstractManager.h>
#include <Corrade/Utility/FormatStl.h>

CORRADE_PLUGIN_REGISTER(VisorInputPcap, visor::input::pcap::PcapInputModulePlugin,
    "visor.module.input/1.0")

namespace visor::input::pcap {

void PcapInputModulePlugin::setup_routes(HttpServer *svr)
{

    // CREATE
    svr->Post("/api/v1/inputs/pcap", std::bind(&PcapInputModulePlugin::_create, this, std::placeholders::_1, std::placeholders::_2));

    // DELETE
    svr->Delete("/api/v1/inputs/pcap/(\\w+)", std::bind(&PcapInputModulePlugin::_delete, this, std::placeholders::_1, std::placeholders::_2));

    // GET
    svr->Get("/api/v1/inputs/pcap/(\\w+)", std::bind(&PcapInputModulePlugin::_read, this, std::placeholders::_1, std::placeholders::_2));
}

void PcapInputModulePlugin::_create(const httplib::Request &req, httplib::Response &res)
{
    json result;
    try {
        auto body = json::parse(req.body);
        // TODO refactor to use instantiate() below
        std::unordered_map<std::string, std::string> schema = {
            {"name", "\\w+"},
            {"iface", "\\w+"}};
        std::unordered_map<std::string, std::string> opt_schema = {
            {"pcap_source", "[_a-z]+"}};
        try {
            check_schema(body, schema, opt_schema);
        } catch (const SchemaException &e) {
            res.status = 400;
            result["error"] = e.what();
            res.set_content(result.dump(), "text/json");
            return;
        }
        if (registry()->input_manager()->module_exists(body["name"])) {
            res.status = 400;
            result["error"] = "input name already exists";
            res.set_content(result.dump(), "text/json");
            return;
        }
        std::string bpf;
        if (body.contains("bpf")) {
            bpf = body["bpf"];
        }

        {
            auto input_stream = std::make_unique<PcapInputStream>(body["name"]);
            input_stream->config_set("iface", body["iface"].get<std::string>());
            input_stream->config_set("bpf", bpf);
            if (body.contains("pcap_source")) {
                input_stream->config_set("pcap_source", body["pcap_source"].get<std::string>());
            }
            input_stream->start();
            registry()->input_manager()->module_add(std::move(input_stream));
        }

        auto [input_stream, stream_mgr_lock] = registry()->input_manager()->module_get_locked(body["name"]);
        assert(input_stream);
        input_stream->info_json(result);
        res.set_content(result.dump(), "text/json");
    } catch (const std::exception &e) {
        res.status = 500;
        result["error"] = e.what();
        res.set_content(result.dump(), "text/json");
    }
}
void PcapInputModulePlugin::_read(const httplib::Request &req, httplib::Response &res)
{
    json result;
    try {
        auto name = req.matches[1];
        if (!registry()->input_manager()->module_exists(name)) {
            res.status = 404;
            result["error"] = "input name does not exist";
            res.set_content(result.dump(), "text/json");
            return;
        }
        auto [input_stream, stream_mgr_lock] = registry()->input_manager()->module_get_locked(name);
        assert(input_stream);
        input_stream->info_json(result);
        res.set_content(result.dump(), "text/json");
    } catch (const std::exception &e) {
        res.status = 500;
        result["error"] = e.what();
        res.set_content(result.dump(), "text/json");
    }
}
void PcapInputModulePlugin::_delete(const httplib::Request &req, httplib::Response &res)
{
    json result;
    try {
        auto name = req.matches[1];
        if (!registry()->input_manager()->module_exists(name)) {
            res.status = 404;
            result["error"] = "input name does not exist";
            res.set_content(result.dump(), "text/json");
            return;
        }
        auto [input_stream, stream_mgr_lock] = registry()->input_manager()->module_get_locked(name);
        assert(input_stream);
        auto count = input_stream->consumer_count();
        if (count) {
            res.status = 400;
            result["error"] = Corrade::Utility::formatString("input stream has existing consumers ({}), remove them first", count);
            res.set_content(result.dump(), "text/json");
            return;
        }
        // manually unlock so we can remove
        stream_mgr_lock.unlock();
        registry()->input_manager()->module_remove(name);
        res.set_content(result.dump(), "text/json");
    } catch (const std::exception &e) {
        res.status = 500;
        result["error"] = e.what();
        res.set_content(result.dump(), "text/json");
    }
}

std::unique_ptr<InputStream> PcapInputModulePlugin::instantiate(const std::string name, const Configurable *config)
{
    auto input_stream = std::make_unique<PcapInputStream>(name);
    input_stream->config_merge(*config);
    return input_stream;
}

}
