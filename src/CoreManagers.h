/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "HandlerModulePlugin.h"
#include "InputModulePlugin.h"
#include "Policies.h"
#include "Taps.h"
#include <vector>

namespace visor {

class CoreManagers
{

    // these hold plugin instances: these are the types of modules available for instantiation
    InputPluginRegistry _input_registry;
    std::vector<InputPluginPtr> _input_plugins;

    HandlerPluginRegistry _handler_registry;
    std::vector<HandlerPluginPtr> _handler_plugins;

    // these hold instances of active modules
    std::unique_ptr<InputStreamManager> _input_manager;
    std::unique_ptr<HandlerManager> _handler_manager;

    std::unique_ptr<TapManager> _tap_manager;
    std::unique_ptr<PolicyManager> _policy_manager;

    std::shared_ptr<spdlog::logger> _logger;
    HttpServer *_svr;

public:
    CoreManagers(HttpServer *svr);
    ~CoreManagers();

    void configure_from_file(const std::string &filename);

    [[nodiscard]] const InputStreamManager *input_manager() const
    {
        return _input_manager.get();
    }
    [[nodiscard]] const HandlerManager *handler_manager() const
    {
        return _handler_manager.get();
    }
    [[nodiscard]] const TapManager *tap_manager() const
    {
        return _tap_manager.get();
    }
    [[nodiscard]] const PolicyManager *policy_manager() const
    {
        return _policy_manager.get();
    }
    [[nodiscard]] const InputPluginRegistry *input_plugin_registry() const
    {
        return &_input_registry;
    }

    [[nodiscard]] InputStreamManager *input_manager()
    {
        return _input_manager.get();
    }

    [[nodiscard]] HandlerManager *handler_manager()
    {
        return _handler_manager.get();
    }

    [[nodiscard]] TapManager *tap_manager()
    {
        return _tap_manager.get();
    }
    [[nodiscard]] PolicyManager *policy_manager()
    {
        return _policy_manager.get();
    }
};

}