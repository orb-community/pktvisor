/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "SflowInputModulePlugin.h"
#include "CoreRegistry.h"
#include "InputStreamManager.h"
#include <Corrade/PluginManager/AbstractManager.h>

CORRADE_PLUGIN_REGISTER(VisorInputSflow, visor::input::sflow::SflowInputModulePlugin,
    "visor.module.input/1.0")

namespace visor::input::sflow {

void SflowInputModulePlugin::setup_routes([[maybe_unused]] HttpServer *svr)
{
}

std::unique_ptr<InputStream> SflowInputModulePlugin::instantiate(const std::string name, const Configurable *config)
{
    auto input_stream = std::make_unique<SflowInputStream>(name);
    input_stream->config_merge(*config);
    return input_stream;
}

}
