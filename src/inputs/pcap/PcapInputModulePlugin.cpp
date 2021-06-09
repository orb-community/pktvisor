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
    // GET
    svr->Get("/api/v1/inputs/pcap/(\\w+)", std::bind(&PcapInputModulePlugin::_read, this, std::placeholders::_1, std::placeholders::_2));
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

std::unique_ptr<InputStream> PcapInputModulePlugin::instantiate(const std::string name, const Configurable *config)
{
    auto input_stream = std::make_unique<PcapInputStream>(name);
    input_stream->config_merge(*config);
    return input_stream;
}

}
