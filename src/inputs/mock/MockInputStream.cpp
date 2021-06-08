/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "MockInputStream.h"

namespace visor::input::mock {

MockInputStream::MockInputStream(const std::string &name)
    : visor::InputStream(name)
{
}

void MockInputStream::start()
{

    if (_running) {
        return;
    }

    _running = true;
}

void MockInputStream::stop()
{
    if (!_running) {
        return;
    }

    _running = false;
}

void MockInputStream::info_json(json &j) const
{
    common_info_json(j);
}

}
