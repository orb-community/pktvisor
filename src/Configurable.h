/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <atomic>
#include <exception>
#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <regex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <variant>
#include <yaml-cpp/yaml.h>

namespace visor {

using json = nlohmann::json;

class ConfigException : public std::runtime_error
{
public:
    explicit ConfigException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

class Configurable
{
private:
    std::unordered_map<std::string, std::variant<std::string, uint64_t, bool>> _config;
    mutable std::shared_mutex _config_mutex;

public:
    template <class T>
    auto config_get(const std::string &key)
    {
        std::shared_lock lock(_config_mutex);
        if (_config.count(key) == 0) {
            throw ConfigException(fmt::format("missing key: {}", key));
        }
        auto val = std::get_if<T>(&_config[key]);
        if (!val) {
            throw ConfigException(fmt::format("wrong type for key: {}", key));
        }
        return *val;
    }

    template <class T>
    void config_set(const std::string &key, const T &val)
    {
        std::unique_lock lock(_config_mutex);
        _config[key] = val;
    }

    // specialize to ensure a string literal is interpreted as a std::string
    void config_set(const std::string &key, const char *val)
    {
        std::unique_lock lock(_config_mutex);
        _config[key] = std::string(val);
    }

    bool config_exists(const std::string &name) const
    {
        std::shared_lock lock(_config_mutex);
        return _config.count(name) == 1;
    }

    void config_json(json &j) const
    {
        std::shared_lock lock(_config_mutex);
        for (const auto &[key, value] : _config) {
            std::visit([&j, key = key](auto &&arg) {
                j[key] = arg;
            },
                value);
        }
    }

    void config_set_yaml(const YAML::Node &config_yaml)
    {
        std::unique_lock lock(_config_mutex);
        assert(config_yaml.IsMap());
        for (YAML::const_iterator it = config_yaml.begin(); it != config_yaml.end(); ++it) {
            auto key = it->first.as<std::string>();

            if (!it->second.IsScalar()) {
                throw ConfigException(fmt::format("invalid value for key: {}", key));
            }

            auto value = it->second.as<std::string>();

            // the yaml library doesn't discriminate between scalar types, so we have to do that ourselves
            if (std::regex_match(value, std::regex("[0-9]+"))) {
                _config[key] = it->second.as<uint64_t>();
            } else if (std::regex_match(value, std::regex("true|false", std::regex_constants::icase))) {
                _config[key] = it->second.as<bool>();
            } else {
                _config[key] = value;
            }
        }
    }
};

}
