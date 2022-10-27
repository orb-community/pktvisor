/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef _WIN32
#elifdef __APPLE__
#include <pthread.h>
#elifdef __linux__
#include <pthread.h>
#endif
#include <string>

namespace visor::thread {

static inline void change_self_name(std::string schema, std::string unique_name)
{
    auto name = schema.substr(0, 1) + "-" + unique_name;
#ifdef _WIN32
#elifdef __APPLE__
    pthread_setname_np(name.substr(0, 15).c_str());
#elifdef __linux__
    pthread_setname_np(pthread_self(), name.substr(0, 15).c_str());
#endif
}

}