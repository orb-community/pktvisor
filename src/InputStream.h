/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractModule.h"
#include "StreamHandler.h"

namespace visor {

class InputStream : public AbstractRunnableModule
{

public:
    InputStream(const std::string &name)
        : AbstractRunnableModule(name)
    {
    }

    virtual ~InputStream(){};

    virtual size_t consumer_count() const = 0;

    void common_info_json(json &j) const
    {
        AbstractModule::common_info_json(j);
        j["input"]["running"] = running();
        j["input"]["consumers"] = consumer_count();
    }
};

}

