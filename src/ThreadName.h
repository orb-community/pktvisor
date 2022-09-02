/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#elif __APPLE__
#include <pthread.h>
#elif __linux__
#include <pthread.h>
#endif
#include <string>

namespace visor::thread {

static inline void change_self_name(std::string schema, std::string unique_name)
{
    auto name = schema.substr(0, 1) + "-" + unique_name;
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#elif __APPLE__
    pthread_setname_np(name.substr(0, 15).c_str());
#elif __linux__
    pthread_setname_np(pthread_self(), name.substr(0, 15).c_str());
#endif
}

}