/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "HandlerModulePlugin.h"

namespace visor::handler::flow {

class FlowHandlerModulePlugin : public HandlerModulePlugin
{

protected:
    void setup_routes(HttpServer *svr) override;

public:
    explicit FlowHandlerModulePlugin(Corrade::PluginManager::AbstractManager &manager, const std::string &plugin)
        : visor::HandlerModulePlugin{manager, plugin}
    {
    }

    std::unique_ptr<StreamHandler> instantiate(const std::string &name, InputCallback *input_stream_cb, const Configurable *config, const Configurable *filter, StreamHandler *stream_handler = nullptr) override;
};
}
