/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include <csv.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <map>
#include <nlohmann/json.hpp>
#include <ostream>
#include <string>

namespace visor::network {

enum Protocol : uint16_t {
    TCP = 1,
    UDP = 2
};

struct PortData {
    std::string name;
    uint16_t lower_bound;
};

struct IpPort {
    static std::map<const uint16_t, PortData> ports_tcp_list;
    static std::map<const uint16_t, PortData> ports_udp_list;

    uint16_t port{0};
    Protocol proto{0};
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(IpPort, port);

    std::string get_service() const;

    static std::string get_service(uint16_t port, Protocol proto);
    static void set_csv_iana_ports(std::string path);

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
