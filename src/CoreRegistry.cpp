/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "CoreRegistry.h"
#include "HandlerManager.h"
#include "InputStreamManager.h"
#include "Policies.h"
#include "Taps.h"
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace visor {

CoreRegistry::CoreRegistry(HttpServer *svr)
    : _svr(svr)
{

    _logger = spdlog::get("visor");
    if (!_logger) {
        _logger = spdlog::stderr_color_mt("visor");
    }

    if (!svr) {
        _logger->warn("initializing modules with no HttpServer");
    }

    // inputs
    _input_manager = std::make_unique<InputStreamManager>();

    // initialize input plugins
    {
        auto alias_list = _input_registry.aliasList();
        auto plugin_list = _input_registry.pluginList();
        std::vector<std::string> by_alias;
        std::set_difference(alias_list.begin(), alias_list.end(),
            plugin_list.begin(), plugin_list.end(), std::inserter(by_alias, by_alias.begin()));
        for (auto &s : by_alias) {
            InputPluginPtr mod = _input_registry.instantiate(s);
            _logger->info("Load input stream plugin: {} {}", s, mod->pluginInterface());
            mod->init_plugin(this, _svr);
            _input_plugins.insert({s, std::move(mod)});
        }
    }

    // handlers
    _handler_manager = std::make_unique<HandlerManager>();

    // initialize handler plugins
    {
        auto alias_list = _handler_registry.aliasList();
        auto plugin_list = _handler_registry.pluginList();
        std::vector<std::string> by_alias;
        std::set_difference(alias_list.begin(), alias_list.end(),
            plugin_list.begin(), plugin_list.end(), std::inserter(by_alias, by_alias.begin()));
        for (auto &s : by_alias) {
            HandlerPluginPtr mod = _handler_registry.instantiate(s);
            _logger->info("Load stream handler plugin: {} {}", s, mod->pluginInterface());
            mod->init_plugin(this, _svr);
            _handler_plugins.insert({s, std::move(mod)});
        }
    }

    // taps
    _tap_manager = std::make_unique<TapManager>(this);
    // collection policies
    _policy_manager = std::make_unique<PolicyManager>(this);
}

visor::CoreRegistry::~CoreRegistry()
{
    // gracefully close all inputs and handlers
    auto [input_modules, im_lock] = _input_manager->module_get_all_locked();
    for (auto &[name, mod] : input_modules) {
        if (mod->running()) {
            _logger->info("Stopping input instance: {}", mod->name());
            mod->stop();
        }
    }
    auto [handler_modules, hm_lock] = _handler_manager->module_get_all_locked();
    for (auto &[name, mod] : handler_modules) {
        if (mod->running()) {
            _logger->info("Stopping handler instance: {}", mod->name());
            mod->stop();
        }
    }
}

void visor::CoreRegistry::configure_from_file(const std::string &filename)
{
    YAML::Node config_file = YAML::LoadFile(filename);

    if (!config_file.IsMap() || !config_file["visor"]) {
        throw ConfigException("invalid schema");
    }
    if (!config_file["version"] || !config_file["version"].IsScalar() || config_file["version"].as<std::string>() != "1.0") {
        throw ConfigException("missing or unsupported version");
    }

    // taps
    if (config_file["visor"]["taps"] && config_file["visor"]["taps"].IsMap()) {
        _tap_manager->load(config_file["visor"]["taps"], true);
    }
}

}