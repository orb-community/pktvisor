/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "utils.h"
#include <IpUtils.h>
#include <cstring>
#include <sstream>

namespace visor::input::pcap {

template <typename Out>
static void split(const std::string &s, char delim, Out result)
{
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}

static std::vector<std::string> split(const std::string &s, char delim)
{
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

static void ipv4_netmask(struct in_addr *netmask, int hostBits)
{
    netmask->s_addr = 0;
    if (hostBits <= 0) {
        return;
    }
    if (hostBits > 32) {
        hostBits = 32;
    }
    netmask->s_addr = htonl(0xFFFFFFFF << (32 - hostBits));
}

static void ipv6_netmask(struct in6_addr *netmask, int hostBits)
{
    uint32_t *p_netmask;
    memset(netmask, 0, sizeof(struct in6_addr));
    if (hostBits < 0) {
        hostBits = 0;
    } else if (hostBits > 128) {
        hostBits = 128;
    }
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    p_netmask = reinterpret_cast<uint32_t *>(netmask->s6_words[0]);
#elif defined(__linux__)
    p_netmask = &netmask->s6_addr32[0];
#else
    p_netmask = &netmask->__u6_addr.__u6_addr32[0];
#endif
    while (hostBits > 32) {
        *p_netmask = 0xffffffff;
        p_netmask++;
        hostBits -= 32;
    }
    if (hostBits != 0) {
        *p_netmask = htonl(0xFFFFFFFF << (32 - hostBits));
    }
}

void parseHostSpec(const std::string &spec, IPv4subnetList &ipv4List, IPv6subnetList &ipv6List)
{
    std::vector<std::string> hosts = split(spec, ',');
    for (auto &host : hosts) {
        if (host.find('/') == host.npos) {
            std::stringstream err;
            err << "invalid CIDR: " << host;
            throw std::runtime_error(err.str());
        }
        std::vector<std::string> cidr = split(host, '/');
        if (cidr.size() != 2) {
            std::stringstream err;
            err << "invalid CIDR: " << host;
            throw std::runtime_error(err.str());
        }
        if (host.find(':') != host.npos) {
            pcpp::IPv6Address net(cidr[0]);
            if (!net.isValid()) {
                std::stringstream err;
                err << "invalid IPv6 address: " << cidr[0];
                throw std::runtime_error(err.str());
            }
            in6_addr mask_addr;
            ipv6_netmask(&mask_addr, std::stoi(cidr[1]));
            char buf[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &mask_addr, buf, INET6_ADDRSTRLEN) == nullptr) {
                std::stringstream err;
                err << "invalid IPv6 address mask: " << cidr[1];
                throw std::runtime_error(err.str());
            }
            ipv6List.emplace_back(IPv6subnet(net, std::stoi(cidr[1])));
        } else {
            pcpp::IPv4Address net(cidr[0]);
            if (!net.isValid()) {
                std::stringstream err;
                err << "invalid IPv4 address: " << cidr[0];
                throw std::runtime_error(err.str());
            }
            in_addr mask_addr;
            ipv4_netmask(&mask_addr, std::stoi(cidr[1]));
            char buf[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &mask_addr, buf, INET_ADDRSTRLEN) == nullptr) {
                std::stringstream err;
                err << "invalid IPv4 address mask: " << cidr[1];
                throw std::runtime_error(err.str());
            }
            ipv4List.emplace_back(IPv4subnet(net, pcpp::IPv4Address(buf)));
        }
    }
}

bool IPv4tosockaddr(const pcpp::IPv4Address &ip, struct sockaddr_in *sa)
{
    memset(sa, 0, sizeof(struct sockaddr_in));
    uint32_t ip_int(ip.toInt());
    memcpy(&sa->sin_addr, &ip_int, sizeof(sa->sin_addr));
    sa->sin_family = AF_INET;
    return true;
}

bool IPv6tosockaddr(const pcpp::IPv6Address &ip, struct sockaddr_in6 *sa)
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