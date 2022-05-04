/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractModule.h"
#include "StreamHandler.h"
#include <sigslot/signal.hpp>

namespace visor {

class InputStream : public AbstractRunnableModule
{
    mutable std::shared_mutex _input_mutex;
    std::vector<const Policy *> _policies;

public:
    enum class Action {
        AddPolicy,
        RemovePolicy
    };

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

    virtual size_t consumer_count() const
    {
        return policy_signal.slot_count() + running_signal.slot_count();
    }

    void common_info_json(json &j) const
    {
        AbstractModule::common_info_json(j);
        j["input"]["running"] = running();
        j["input"]["consumers"] = consumer_count();
    }

    mutable sigslot::signal<const Policy *, Action> policy_signal;
    mutable sigslot::signal<const timespec> running_signal;
};

}
