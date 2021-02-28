/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "AbstractModule.h"
#include "StreamHandler.h"

namespace vizer {

class InputStream : public AbstractModule
{

public:
    InputStream(const std::string &name)
        : AbstractModule(name)
    {
    }

    virtual ~InputStream(){};

    // TODO this should be const, currently limited by slot architecture
    virtual size_t consumer_count() = 0;

    void _common_info_json(json &j) const
    {
        AbstractModule::_common_info_json(j);
        // TODO const correctness on consumer count
        j["input"]["consumers"] = const_cast<InputStream *>(this)->consumer_count();
    }
};

}

