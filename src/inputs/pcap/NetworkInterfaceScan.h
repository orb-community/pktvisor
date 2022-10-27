/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#ifdef _WIN32
#elifdef __APPLE__
#include <net/if.h>
#include <ifaddrs.h>
#elifdef __linux__
#include <net/if.h>
#include <linux/if_link.h>
#include <ifaddrs.h>
#endif
#include <string>

namespace visor::input::pcap {

static inline std::string most_used_interface()
{
#ifdef _WIN32
    return std::string();
#elifdef __APPLE__
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
            if_data *stats = reinterpret_cast<if_data *>(ifa->ifa_data);
            auto packets = stats->ifi_ipackets + stats->ifi_opackets;
            if (packets > most_used) {
                most_used = packets;
                interface = std::string(ifa->ifa_name);
            }
        }
    }
    freeifaddrs(ifaddr);
    return interface;
#elifdef __linux__
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