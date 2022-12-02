/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include <stdexcept>
#include <string>

#pragma once

namespace visor::input::pcap {

class PcapException : public std::runtime_error
{
public:
    PcapException(const char *msg)
        : std::runtime_error(msg)
    {
    }
    PcapException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

}