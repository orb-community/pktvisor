/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#elif defined(__APPLE__) || defined(__linux__)
#include <netdb.h>
#endif
#include <nlohmann/json.hpp>
#include <ostream>
#include <string>

namespace visor {

enum Protocol : uint16_t {
    TCP = 1,
    UDP = 2
};

struct IpPort {
    uint16_t port{0};
    Protocol proto{0};
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(IpPort, port);

    std::string get_name() const;

    bool operator==(const IpPort &other) const
    {
        return (port == other.port
            && proto == other.proto);
    }

    friend std::ostream &operator<<(std::ostream &os, const IpPort &p);
};

}

template <>
struct std::hash<visor::IpPort> {
    std::size_t operator()(const visor::IpPort &p) const
    {
        return std::hash<uint32_t>{}((p.proto << 16) + p.port);
    }
};