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

void MockInputModulePlugin::setup_routes([[maybe_unused]] HttpServer *svr)
{
}

std::unique_ptr<InputStream> MockInputModulePlugin::instantiate(const std::string name, const Configurable *config, const Configurable *filter)
{
    auto input_stream = std::make_unique<MockInputStream>(name);
    input_stream->config_merge(*config);
    input_stream->config_merge(*filter);
    return input_stream;
}

std::string MockInputModulePlugin::generate_input_name(std::string prefix, const Configurable &config, [[maybe_unused]] const Configurable &filter)
{
    return prefix + "-" + config.config_hash();
}

}
