/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "MockInputModulePlugin.h"
#include "CoreRegistry.h"
#include "InputStreamManager.h"
#include <Corrade/PluginManager/AbstractManager.h>
#include <Corrade/Utility/FormatStl.h>

CORRADE_PLUGIN_REGISTER(VisorInputMock, visor::input::mock::MockInputModulePlugin,
    "visor.module.input/1.0")

namespace visor::input::mock {

void MockInputModulePlugin::setup_routes(HttpServer *svr)
{


}

std::unique_ptr<InputStream> MockInputModulePlugin::instantiate(const Configurable *config)
{
    json body;
    config->config_json(body);
    std::unordered_map<std::string, std::string> schema = {
        {"name", "\\w+"},
        {"iface", "\\w+"}};
    std::unordered_map<std::string, std::string> opt_schema = {
        {"mock_source", "[_a-z]+"}};
    // will throw on error
    check_schema(body, schema, opt_schema);
    auto input_stream = std::make_unique<MockInputStream>(body["name"]);
    std::string bpf;
    if (body.contains("bpf")) {
        bpf = body["bpf"];
    }
    input_stream->config_set("iface", body["iface"].get<std::string>());
    input_stream->config_set("bpf", bpf);
    if (body.contains("mock_source")) {
        input_stream->config_set("mock_source", body["mock_source"].get<std::string>());
    }
    return input_stream;
}

}
