/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractModule.h"
#include <sigslot/signal.hpp>

namespace visor {

enum class Action {
    AddPolicy,
    RemovePolicy
};

class InputEventProxy : public Configurable
{
protected:
    std::string _input_name;
    std::string _filter_hash;

public:
    InputEventProxy(const std::string &name, const Configurable &filter)
        : _input_name(name)
    {
        config_merge(filter);
        _filter_hash = config_hash();
    };
    virtual ~InputEventProxy() = default;

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
}