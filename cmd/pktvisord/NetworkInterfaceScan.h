/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#elif __APPLE__
#include <net/if.h>
#include <ifaddrs.h>
#elif __linux__
#include <net/if.h>
#include <linux/if_link.h>
#include <ifaddrs.h>
#endif
#include <string>

namespace visor {

static inline std::string most_used_interface()
{
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    return std::string();
#elif __APPLE__
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
        if (int family = ifa->ifa_addr->sa_family; family == AF_LINK && ifa->ifa_data != nullptr) {
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
#elif __linux__
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
        if (int family = ifa->ifa_addr->sa_family; family == AF_PACKET && ifa->ifa_data != nullptr) {
            struct rtnl_link_stats *stats = reinterpret_cast<rtnl_link_stats *>(ifa->ifa_data);
            uint64_t packets = stats->tx_packets + stats->rx_packets;
            if (packets > most_used) {
                most_used = packets;
                interface = std::string(ifa->ifa_name);
            }
        }
    }
    freeifaddrs(ifaddr);
    return interface;
#endif
}

}