/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

namespace visor::input::dnstap {

class DnstapException : public std::runtime_error
{
public:
    DnstapException(const char *msg)
        : std::runtime_error(msg)
    {
    }

    DnstapException(std::string msg)
        : std::runtime_error(msg)
    {
    }
};

}