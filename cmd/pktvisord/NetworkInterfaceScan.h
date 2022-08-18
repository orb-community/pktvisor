/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#if __has_include(<ifaddrs.h>)
#include <net/if.h>
#include <ifaddrs.h>
#else
// System without ifaddrs
#endif
#include <string>

namespace visor {

static inline std::string most_used_interface()
{
#if __has_include(<ifaddrs.h>)
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        return std::string();
    }
    std::string interface;
    uint64_t most_used = 0;
    for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || (ifa->ifa_flags & IFF_LOOPBACK) || !(ifa->ifa_flags & IFF_UP)) {
            continue;
        }
#if defined(AF_PACKET)
        if (int family = ifa->ifa_addr->sa_family; family == AF_PACKET && ifa->ifa_data != nullptr) {
#elif defined(AF_LINK)
        if (int family = ifa->ifa_addr->sa_family; family == AF_LINK && ifa->ifa_data != nullptr) {
#else
        if (false) {
#endif
            uint32_t *stats = reinterpret_cast<uint32_t *>(ifa->ifa_data);
            // first 4 bytes are txpackets and next 4 bytes are rxpackets
            uint64_t packets = stats[0] + stats[1];
            if (packets > most_used) {
                most_used = packets;
                interface = std::string(ifa->ifa_name);
            }
        }
    }
    freeifaddrs(ifaddr);
    return interface;
#else
    return std::string();
#endif
}

}