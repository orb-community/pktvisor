/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractManager.h"
#include "AbstractModule.h"
#include "Configurable.h"
#include "HandlerModulePlugin.h"
#include "InputModulePlugin.h"
#include "Taps.h"
#include <map>
#include <vector>
#include <yaml-cpp/yaml.h>

namespace visor {

class CoreRegistry;

class PolicyException : public std::runtime_error
{
public:
    explicit PolicyException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

class Policy : public AbstractRunnableModule
{
    static constexpr size_t HANDLERS_SEQUENCE_SIZE = 1;

    std::vector<Tap *> _taps;
    std::vector<InputStream *> _input_streams;
    bool _modules_sequence;
    std::vector<AbstractRunnableModule *> _modules;

public:
    Policy(const std::string &name)
        : AbstractRunnableModule(name)
        , _modules_sequence(false)
    {
    }

    std::string schema_key() const override
    {
        return "policy";
    }

    void set_modules_sequence(bool sequence)
    {
        _modules_sequence = sequence;
    }

    void add_tap(Tap *tap)
    {
        _taps.push_back(tap);
    }

    void add_input_stream(InputStream *input_stream)
    {
        _input_streams.push_back(input_stream);
    }

    const std::vector<InputStream *> &input_stream() const
    {
        return _input_streams;
    }

    void add_module(AbstractRunnableModule *m)
    {
        _modules.push_back(m);
    }

    const std::vector<AbstractRunnableModule *> &modules()
    {
        return _modules;
    }

    size_t get_handlers_list_size() const
    {
        if (_modules_sequence) {
            return HANDLERS_SEQUENCE_SIZE;
        } else {
            return _modules.size();
        }
    }

    // life cycle
    void start() override;
    void stop() override;

    void info_json(json &j) const override;
};

class PolicyManager : public AbstractManager<Policy>
{
    mutable std::mutex _load_mutex;

    CoreRegistry *_registry;

    /**
     * the default number of periods we will maintain in the window for handlers
     */
    unsigned int _default_num_periods{5};
    uint32_t _default_deep_sample_rate{100};
    std::map<std::string, std::unique_ptr<Configurable>> _global_handler_config;

    struct HandlerData {
        std::string name;
        std::string type;
        Config config;
        Config filter;
    };

    void _validate_policy(const YAML::Node &policy_yaml, const std::string &policy_name, Policy *policy_ptr, Tap *tap = nullptr);
    HandlerData _validate_handler(const YAML::const_iterator &hander_iterator, const std::string &policy_name, Config &window_config, bool sequence);

public:
    PolicyManager(CoreRegistry *registry)
        : _registry(registry)
    {
    }

    virtual ~PolicyManager()
    {
    }

    void set_default_num_periods(unsigned int n)
    {
        _default_num_periods = n;
    }
    void set_default_deep_sample_rate(uint32_t r)
    {
        _default_deep_sample_rate = r;
    }

    unsigned int default_num_periods() const
    {
        return _default_num_periods;
    }

    uint32_t default_deep_sample_rate() const
    {
        return _default_deep_sample_rate;
    }

    void set_default_handler_config(const YAML::Node &config_yaml);
    std::vector<Policy *> load_from_str(const std::string &str);
    std::vector<Policy *> load(const YAML::Node &tap_yaml);
    void remove_policy(const std::string &name);
};

}