/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef _WIN32
#elif defined(__APPLE__) || defined(__linux__)
#include <netdb.h>
#endif
#include <nlohmann/json.hpp>
#include <ostream>
#include <string>

namespace visor::network {

enum Protocol : uint16_t {
    TCP = 1,
    UDP = 2
};

struct IpPort {
    static inline const uint16_t BEGIN_DYNAMIC_PORT = 49152;
    static inline const uint16_t END_DYNAMIC_PORT = 65535;
    uint16_t port{0};
    Protocol proto{0};
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(IpPort, port);

    std::string get_service() const;

    bool operator==(const IpPort &other) const
    {
        return (port == other.port
            && proto == other.proto);
    }

    friend std::ostream &operator<<(std::ostream &os, const IpPort &p);
};

}

template <>
struct std::hash<visor::network::IpPort> {
    std::size_t operator()(const visor::network::IpPort &p) const
    {
        return std::hash<uint32_t>{}((p.proto << 16) + p.port);
    }
};