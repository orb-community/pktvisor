/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "Configurable.h"

namespace visor {

class Tap : public Configurable
{
protected:
    /**
     * the tap identifier: unique name associated with this Tap
     */
    std::string _name;

public:
    Tap(const std::string &name);
};

class TapManager
{
};

}