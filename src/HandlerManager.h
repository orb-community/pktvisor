/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractManager.h"
#include "StreamHandler.h"

namespace vizer {

/**
 * called from HTTP threads so must be thread safe
 */
class HandlerManager : public AbstractManager<StreamHandler>
{

public:
    HandlerManager()
        : AbstractManager<StreamHandler>()
    {
    }

    virtual ~HandlerManager()
    {
    }
};

}

