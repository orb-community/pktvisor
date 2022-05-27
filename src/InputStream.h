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
    std::string _filter_hash;

public:
    InputCallback(const std::string &name, const Configurable &filter)
        : _input_name(name)
    {
        config_merge(filter);
        _filter_hash = config_hash();
    };
    virtual ~InputCallback() = default;

    const std::string &name() const
    {
        return _input_name;
    }

    const std::string &hash() const
    {
        return _filter_hash;
    }

    void policy_cb(const Policy *policy, Action action)
    {
        policy_signal(policy, action);
    }

    void heartbeat_cb(const timespec stamp)
    {
        heartbeat_signal(stamp);
    }

    virtual size_t consumer_count() const
    {
        return policy_signal.slot_count() + heartbeat_signal.slot_count();
    }

    mutable sigslot::signal<const Policy *, Action> policy_signal;
    mutable sigslot::signal<const timespec> heartbeat_signal;
};

class InputStream : public AbstractRunnableModule
{

    std::vector<const Policy *> _policies;

protected:
    static constexpr uint8_t HEARTBEAT_INTERVAL = 30; // in seconds
    mutable std::shared_mutex _input_mutex;
    std::vector<std::unique_ptr<InputCallback>> _callbacks;

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
        for (auto const &callback : _callbacks) {
            callback->policy_cb(policy, Action::AddPolicy);
        }
    }

    void remove_policy(const Policy *policy)
    {
        std::unique_lock lock(_input_mutex);
        _policies.erase(std::remove(_policies.begin(), _policies.end(), policy), _policies.end());
        for (auto const &callback : _callbacks) {
            callback->policy_cb(policy, Action::RemovePolicy);
        }
    }

    size_t policies_count() const
    {
        std::unique_lock lock(_input_mutex);
        return _policies.size();
    }

    size_t consumer_count() const
    {
        std::unique_lock lock(_input_mutex);
        size_t count = 0;
        for (auto const &callback : _callbacks) {
            count = callback->consumer_count();
        }
        return count;
    }

    InputCallback *add_callback(const Configurable &filter)
    {
        std::unique_lock lock(_input_mutex);
        auto hash = filter.config_hash();
        for (auto const &callback : _callbacks) {
            if (callback->hash() == hash) {
                return callback.get();
            }
        }
        _callbacks.push_back(create_callback(filter));
        return _callbacks.back().get();
    }

    virtual std::unique_ptr<InputCallback> create_callback(const Configurable &filter) = 0;

    void common_info_json(json &j) const
    {
        AbstractModule::common_info_json(j);
        j["input"]["running"] = running();
    }
};

}
