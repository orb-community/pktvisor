/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "HandlerModulePlugin.h"
#include "InputModulePlugin.h"
#include "Policies.h"
#include "Taps.h"
#include <map>

namespace visor {

class InputStreamManager;
class HandlerManager;

/**
 * The "registry" of core data structures such as plugins, modules, taps and policies
 */
class CoreRegistry
{

    // this is the interface to load/instantiate/unload Corrade plugins
    InputPluginRegistry _input_registry;
    HandlerPluginRegistry _handler_registry;

    // these hold instantiated Corrade plugin instances: they know how to instantiate visor::AbstractModule derived instances
    // keyed by plugin alias name
    std::map<std::string, InputPluginPtr> _input_plugins;
    std::map<std::string, HandlerPluginPtr> _handler_plugins;

    // these hold instances of active visor::AbstractModule derived modules (the main event processors)
    std::unique_ptr<InputStreamManager> _input_manager;
    std::unique_ptr<HandlerManager> _handler_manager;

    // taps and policies
    std::unique_ptr<TapManager> _tap_manager;
    std::unique_ptr<PolicyManager> _policy_manager;

    std::shared_ptr<spdlog::logger> _logger;
    HttpServer *_svr;

public:
    CoreRegistry(HttpServer *svr);
    ~CoreRegistry();

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