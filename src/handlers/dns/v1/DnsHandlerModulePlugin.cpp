/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DnsHandlerModulePlugin.h"
#include "CoreRegistry.h"
#include "Corrade/PluginManager/AbstractManager.h"
#include "DnsStreamHandler.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "nlohmann/json.hpp"

CORRADE_PLUGIN_REGISTER(VisorHandlerDnsV1, visor::handler::dns::v1::DnsHandlerModulePlugin,
    "visor.module.handler/1.0")

namespace visor::handler::dns::v1 {

using namespace visor::input::pcap;
using json = nlohmann::json;

void DnsHandlerModulePlugin::setup_routes(HttpServer *svr)
{
}
std::unique_ptr<StreamHandler> DnsHandlerModulePlugin::instantiate(const std::string &name, InputEventProxy *proxy, const Configurable *config, const Configurable *filter)
{
    // TODO using config as both window config and module config
    auto handler_module = std::make_unique<DnsStreamHandler>(name, proxy, config);
    handler_module->config_merge(*config);
    handler_module->config_merge(*filter);
    return handler_module;
}

}