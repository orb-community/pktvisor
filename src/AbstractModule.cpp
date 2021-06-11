/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "AbstractModule.h"
#include "Policies.h"

namespace visor {

void AbstractRunnableModule::info_json(json &j) const
{
    common_info_json(j);
}

void AbstractRunnableModule::common_info_json(json &j) const
{
    j["module"]["name"] = _name;
    j["module"]["running"] = _running.load();
    if (_policy) {
        j["module"]["policy"]["name"] = _policy->name();
    }
    config_json(j["module"]["config"]);
}

}