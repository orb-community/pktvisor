#pragma once

#include <atomic>
#include <exception>
#include <nlohmann/json.hpp>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <variant>

namespace vizer {

using json = nlohmann::json;

class ConfigException : public std::runtime_error
{
public:
    explicit ConfigException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

class AbstractModule
{
private:
    std::unordered_map<std::string, std::variant<std::string, uint64_t, bool>> _config;
    mutable std::shared_mutex _config_mutex;

protected:
    std::atomic_bool _running = false;
    std::string _name;

public:
    AbstractModule(const std::string &name)
        : _name(name)
    {
    }

    virtual ~AbstractModule(){};

    virtual void start() = 0;
    virtual void stop() = 0;

    virtual json info_json() const = 0;

    const std::string &name() const
    {
        return _name;
    }

    bool running() const
    {
        return _running;
    }

    template <class T>
    auto config_get(const std::string &key)
    {
        std::shared_lock lock(_config_mutex);
        if (_config.count(key) == 0) {
            throw ConfigException("missing key: " + key);
        }
        auto val = std::get_if<T>(&_config[key]);
        if (!val) {
            throw ConfigException("wrong type for key: " + key);
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

    json config_json(void) const
    {
        std::shared_lock lock(_config_mutex);
        json result;
        for (const auto &[key, value] : _config) {
            std::visit([&result, key = key](auto &&arg) {
                result[key] = arg;
            },
                value);
        }
        return result;
    }
};

}

