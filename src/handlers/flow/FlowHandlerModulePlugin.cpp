/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "FlowHandlerModulePlugin.h"
#include "CoreRegistry.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "FlowStreamHandler.h"
#include <Corrade/PluginManager/AbstractManager.h>
#include <nlohmann/json.hpp>

CORRADE_PLUGIN_REGISTER(VisorHandlerFlowV1, visor::handler::flow::v1::FlowHandlerModulePlugin,
    "visor.module.handler/1.0")

namespace visor::handler::flow::v1 {

using json = nlohmann::json;

void FlowHandlerModulePlugin::setup_routes(HttpServer *svr)
{
}
std::unique_ptr<StreamHandler> FlowHandlerModulePlugin::instantiate(const std::string &name, InputEventProxy *proxy, const Configurable *config, const Configurable *filter)
{
    // TODO using config as both window config and module config
    auto handler_module = std::make_unique<FlowStreamHandler>(name, proxy, config);
    handler_module->config_merge(*config);
    handler_module->config_merge(*filter);
    return handler_module;
}

}