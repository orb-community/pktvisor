/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "Taps.h"
#include <regex>

visor::Tap::Tap(const std::string &name)
    : _name(name)
{
    if (!std::regex_match(name, std::regex("[a-zA-Z_][a-zA-Z0-9_]*"))) {
        throw std::runtime_error("invalid tap name: " + name);
    }
}
