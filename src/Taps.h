/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractManager.h"
#include "AbstractModule.h"
#include "Configurable.h"

namespace visor {

class Tap : public AbstractModule
{

public:
    Tap(const std::string &name)
        : AbstractModule(name)
    {
    }
};

class TapManager : public AbstractManager<Tap>
{
public:
    virtual ~TapManager()
    {
    }
};

}