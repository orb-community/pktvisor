/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <atomic>
#include <exception>
#include <fmt/core.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <regex>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>
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
public:
    typedef std::vector<std::string> StringList;

private:
    std::unordered_map<std::string, std::variant<std::string, uint64_t, bool, StringList, std::shared_ptr<Configurable>>> _config;
    mutable std::shared_mutex _config_mutex;

public:
    Configurable() = default;
    ~Configurable() = default;

    Configurable(const Configurable &other)
    {
        std::shared_lock rlock(other._config_mutex);
        std::unique_lock wlock(_config_mutex);
        _config = other._config;
    }
    Configurable(Configurable &&other)
    {
        std::unique_lock lock1(other._config_mutex);
        std::unique_lock lock2(_config_mutex);
        _config = std::move(other._config);
    }
    Configurable &operator=(const Configurable &other)
    {
        std::shared_lock rlock(other._config_mutex);
        std::unique_lock wlock(_config_mutex);
        _config = other._config;
        return *this;
    }
    Configurable &operator=(Configurable &&other)
    {
        std::unique_lock lock1(other._config_mutex);
        std::unique_lock lock2(_config_mutex);
        _config = std::move(other._config);
        return *this;
    }

    void config_merge(const Configurable &other)
    {
        std::shared_lock rlock(other._config_mutex);
        std::unique_lock wlock(_config_mutex);
        for (const auto &[key, value] : other._config) {
            _config[key] = value;
        }
    }

    StringList get_all_keys() const
    {
        std::unique_lock lock(_config_mutex);
        StringList list;
        for (const auto &[key, value] : _config) {
            list.push_back(key);
        }
        return list;
    }

    template <class T>
    auto config_get(const std::string &key) const
    {
        std::shared_lock lock(_config_mutex);
        if (_config.count(key) == 0) {
            throw ConfigException(fmt::format("missing key: {}", key));
        }
        auto entry = _config.find(key);
        auto val = std::get_if<T>(&entry->second);
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
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, std::shared_ptr<Configurable>>) {
                    arg->config_json(j[key]);
                } else {
                    j[key] = arg;
                }
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

            if (it->second.IsMap()) {
                auto config = std::make_shared<Configurable>();
                config->config_set_yaml(it->second);
                _config[key] = config;
                continue;
            }

            if (it->second.IsSequence()) {
                StringList sl;
                for (std::size_t i = 0; i < it->second.size(); ++i) {
                    if (!it->second[i].IsScalar()) {
                        throw ConfigException(fmt::format("invalid value for sequence in key: {}", key));
                    }
                    sl.push_back(it->second[i].as<std::string>());
                }
                _config[key] = sl;
                continue;
            }

            // otherwise, scalar
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

    const std::string config_hash() const
    {
        std::shared_lock lock(_config_mutex);
        std::vector<std::string> key_values;
        for (const auto &[key, value] : _config) {
            std::visit([&key_values, key = key](auto &&arg) {
                std::string data;
                data += key;
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, StringList>) {
                    auto temp_list = arg;
                    std::sort(temp_list.begin(), temp_list.end());
                    for (const auto &s : temp_list) {
                        data += s;
                    }
                } else if constexpr (std::is_same_v<T, std::string>) {
                    data += arg;
                } else if constexpr (std::is_same_v<T, std::shared_ptr<Configurable>>) {
                    data += arg->config_hash();
                } else {
                    data += std::to_string(arg);
                }
                key_values.push_back(data);
            },
                value);
        }
        std::sort(key_values.begin(), key_values.end());
        std::string hash;
        for (auto &data : key_values) {
            hash += data;
        }
        auto h1 = std::hash<std::string>{}(hash);
        std::stringstream string_stream;
        string_stream << std::hex << h1;
        return string_stream.str();
    }
};

class Config : public Configurable
{
};

}
