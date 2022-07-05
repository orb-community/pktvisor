/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <IPv4Layer.h>
#include <IPv6Layer.h>

namespace visor::handler::flow {

static inline bool IPv4_to_sockaddr(const pcpp::IPv4Address &ip, struct sockaddr_in *sa)
{
    memset(sa, 0, sizeof(struct sockaddr_in));
    uint32_t ip_int(ip.toInt());
    memcpy(&sa->sin_addr, &ip_int, sizeof(sa->sin_addr));
    sa->sin_family = AF_INET;
    return true;
}

static inline bool IPv6_to_sockaddr(const pcpp::IPv6Address &ip, struct sockaddr_in6 *sa)
{
    memset(sa, 0, sizeof(struct sockaddr_in6));
    auto ip_bytes = ip.toBytes();
    for (int i = 0; i < 16; ++i) {
        sa->sin6_addr.s6_addr[i] = ip_bytes[i];
    }
    sa->sin6_family = AF_INET6;
    return true;
}

}