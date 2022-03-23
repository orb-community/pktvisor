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
    std::map<const Policy *, uint16_t> _policies;

public:
    InputStream(const std::string &name)
        : AbstractRunnableModule(name)
    {
    }

    virtual ~InputStream(){};

    void add_policy(const Policy *policy, uint16_t handlers)
    {
        std::unique_lock lock(_input_mutex);
        _policies[policy] = handlers;
        attached_policies(1, handlers);
    }

    void remove_policy(const Policy *policy)
    {
        std::unique_lock lock(_input_mutex);
        auto iterator = _policies.find(policy);
        if (iterator != _policies.end()) {
            attached_policies(-1, -iterator->second);
            _policies.erase(iterator);
        }
    }

    size_t policies_count() const
    {
        std::unique_lock lock(_input_mutex);
        return _policies.size();
    }

    virtual size_t consumer_count() const
    {
        return attached_policies.slot_count();
    }

    void common_info_json(json &j) const
    {
        AbstractModule::common_info_json(j);
        j["input"]["running"] = running();
        j["input"]["consumers"] = consumer_count();
    }

    mutable sigslot::signal<int16_t, int16_t> attached_policies;
};

}
