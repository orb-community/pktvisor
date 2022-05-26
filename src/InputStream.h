/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractModule.h"
#include "StreamHandler.h"
#include <sigslot/signal.hpp>

namespace visor {

enum class Action {
    AddPolicy,
    RemovePolicy
};

class InputCallback : public Configurable
{
protected:
    std::string _input_name;

public:
    InputCallback(const Configurable &filter)
    {
        config_merge(filter);
    };
    virtual ~InputCallback() = default;

    const std::string &name() const
    {
        return _input_name;
    }
};

class InputStream : public AbstractRunnableModule
{
    mutable std::shared_mutex _input_mutex;
    std::vector<const Policy *> _policies;
    std::map<std::string, std::unique_ptr<InputCallback>> _callbacks;

protected:
    static constexpr uint8_t HEARTBEAT_INTERVAL = 30; // in seconds

public:

    InputStream(const std::string &name)
        : AbstractRunnableModule(name)
    {
    }

    virtual ~InputStream(){};

    void add_policy(const Policy *policy)
    {
        std::unique_lock lock(_input_mutex);
        _policies.push_back(policy);
        policy_signal(policy, Action::AddPolicy);
    }

    void remove_policy(const Policy *policy)
    {
        std::unique_lock lock(_input_mutex);
        _policies.erase(std::remove(_policies.begin(), _policies.end(), policy), _policies.end());
        policy_signal(policy, Action::RemovePolicy);
    }

    size_t policies_count() const
    {
        std::unique_lock lock(_input_mutex);
        return _policies.size();
    }

    InputCallback *add_callback(const Configurable &filter)
    {
        std::unique_lock lock(_input_mutex);
        auto hash = filter.config_hash();
        auto it = _callbacks.find(hash);
        if (it != _callbacks.end()) {
            return it->second.get();
        }
        _callbacks[hash] = create_callback(filter);
        return _callbacks[hash].get();
    }

    virtual std::unique_ptr<InputCallback> create_callback(const Configurable &filter) = 0;

    virtual size_t consumer_count() const
    {
        return policy_signal.slot_count() + heartbeat_signal.slot_count();
    }

    void common_info_json(json &j) const
    {
        AbstractModule::common_info_json(j);
        j["input"]["running"] = running();
        j["input"]["consumers"] = consumer_count();
    }

    mutable sigslot::signal<const Policy *, Action> policy_signal;
    mutable sigslot::signal<const timespec> heartbeat_signal;
};

}
