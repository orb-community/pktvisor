/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractManager.h"
#include "InputStream.h"

namespace vizer {

/**
 * called from HTTP threads so must be thread safe
 */
class InputStreamManager : public AbstractManager<InputStream>
{

public:
    InputStreamManager()
        : AbstractManager<InputStream>()
    {
    }

    virtual ~InputStreamManager()
    {
    }

    // override to atomically ensure we don't remove if there are active consumers
    void module_remove(const std::string &name) override
    {
        std::unique_lock lock(_map_mutex);
        if (_map.count(name) == 0) {
            throw std::runtime_error("module name does not exist");
        }
        if (_map[name]->consumer_count()) {
            throw std::runtime_error("unable to remove, stream has consumers");
        }
        _map[name]->stop();
        _map.erase(name);
    }
};

}
