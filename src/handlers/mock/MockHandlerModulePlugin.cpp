/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "MockHandlerModulePlugin.h"
#include "CoreRegistry.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "MockInputStream.h"
#include "MockStreamHandler.h"
#include <Corrade/PluginManager/AbstractManager.h>
#include <nlohmann/json.hpp>

CORRADE_PLUGIN_REGISTER(VisorHandlerMock, visor::handler::mock::MockHandlerModulePlugin,
    "visor.module.handler/1.0")

namespace visor::handler::mock {

using namespace visor::input::mock;
using json = nlohmann::json;

void MockHandlerModulePlugin::setup_routes(HttpServer *svr)
{
}
std::unique_ptr<StreamHandler> MockHandlerModulePlugin::instantiate(const std::string &name, InputStream *input_stream, const Configurable *config, StreamHandler *stream_handler)
{
    // TODO using config as both window config and module config
    auto handler_module = std::make_unique<MockStreamHandler>(name, input_stream, config, stream_handler);
    return handler_module;
}

}