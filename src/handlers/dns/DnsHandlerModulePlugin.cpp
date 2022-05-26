/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DnsHandlerModulePlugin.h"
#include "CoreRegistry.h"
#include "DnsStreamHandler.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include <Corrade/PluginManager/AbstractManager.h>
#include <nlohmann/json.hpp>

CORRADE_PLUGIN_REGISTER(VisorHandlerDns, visor::handler::dns::DnsHandlerModulePlugin,
    "visor.module.handler/1.0")

namespace visor::handler::dns {

using namespace visor::input::pcap;
using json = nlohmann::json;

void DnsHandlerModulePlugin::setup_routes(HttpServer *svr)
{
}
std::unique_ptr<StreamHandler> DnsHandlerModulePlugin::instantiate(const std::string &name, InputCallback *input_stream_cb, const Configurable *config, const Configurable *filter, StreamHandler *stream_handler)
{
    // TODO using config as both window config and module config
    auto handler_module = std::make_unique<DnsStreamHandler>(name, input_stream_cb, config, stream_handler);
    handler_module->config_merge(*config);
    handler_module->config_merge(*filter);
    return handler_module;
}

}