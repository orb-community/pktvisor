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
    // policies policies
    _policy_manager = std::make_unique<PolicyManager>(this);
}

void CoreRegistry::stop()
{
    // gracefully stop all policies
    auto [policies, lock] = _policy_manager->module_get_all_locked();
    for (auto &[name, policy] : policies) {
        policy->stop();
    }
}

CoreRegistry::~CoreRegistry()
{
    stop();
}

void CoreRegistry::configure_from_yaml(YAML::Node &node)
{

    if (!node.IsMap() || !node["visor"]) {
        throw ConfigException("invalid schema");
    }
    if (!node["version"] || !node["version"].IsScalar() || node["version"].as<std::string>() != "1.0") {
        throw ConfigException("missing or unsupported version");
    }

    // taps
    if (node["visor"]["taps"] && node["visor"]["taps"].IsMap()) {
        _tap_manager->load(node["visor"]["taps"], true);
    }
    // policies
    if (node["visor"]["policies"] && node["visor"]["policies"].IsMap()) {
        auto policies = _policy_manager->load(node["visor"]["policies"]);
    }
}

void CoreRegistry::configure_from_file(const std::string &filename)
{
    YAML::Node config = YAML::LoadFile(filename);
    configure_from_yaml(config);
}
void CoreRegistry::configure_from_str(const std::string &str)
{
    YAML::Node config = YAML::Load(str);
    configure_from_yaml(config);
}

}