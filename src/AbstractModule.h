/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "Configurable.h"
#include <atomic>
#include <exception>
#include <nlohmann/json.hpp>
#include <regex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <variant>

namespace visor {

using json = nlohmann::json;

class AbstractModule : public Configurable
{

protected:
    std::atomic_bool _running = false;

    /**
     * the module instance identifier: unique name associated with this instance
     */
    std::string _name;

    void _common_info_json(json &j) const
    {
        j["module"]["name"] = _name;
        j["module"]["running"] = _running.load();
        config_json(j["module"]["config"]);
    }

public:
    AbstractModule(const std::string &name)
        : _name(name)
    {
        if (!std::regex_match(name, std::regex("[a-zA-Z_][a-zA-Z0-9_]*"))) {
            throw std::runtime_error("invalid module name: " + name);
        }
    }

    virtual ~AbstractModule(){};

    virtual void start() = 0;
    virtual void stop() = 0;

    virtual void info_json(json &j) const = 0;

    const std::string &name() const
    {
        return _name;
    }

    /**
     * the module schema key: the same for all instances of this module
     * used in schemas such as json
     */
    virtual std::string schema_key() const = 0;

    bool running() const
    {
        return _running;
    }
};

}
