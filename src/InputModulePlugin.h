/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractPlugin.h"
#include <memory>
#include <nlohmann/json_fwd.hpp>
#include <string>

namespace visor {

class InputStream;
class Configurable;

class InputModulePlugin : public AbstractPlugin
{
public:
    static std::string pluginInterface()
    {
        return "visor.module.input/1.0";
    }

    explicit InputModulePlugin(std::string alias)
        : AbstractPlugin{std::move(alias)}
    {
    }

    /**
     * Instantiate a new InputStream
     */
    virtual std::unique_ptr<InputStream> instantiate(const std::string name, const Configurable *config, const Configurable *filter) = 0;

    virtual std::string generate_input_name(std::string prefix, const Configurable &config, const Configurable &filter) = 0;

    /**
     * Redact secret-bearing values from a raw config-echo JSON node for this input type.
     * Called wherever a config holding this input's keys is serialized verbatim (e.g.
     * Tap::info_json, exposed via the admin API) so credentials configured for the input
     * (auth headers, proxy URLs, request bodies, ...) never leave the process. Default: no-op.
     */
    virtual void redact_config_json(nlohmann::json &) const
    {
    }
};

using InputPluginPtr = std::unique_ptr<InputModulePlugin>;

}
