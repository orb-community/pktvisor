/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#include <Ws2tcpip.h>
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#include <IpAddress.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace visor::input::pcap {

class PcapException : public std::runtime_error
{
public:
    PcapException(const char *msg)
        : std::runtime_error(msg)
    {
    }
    PcapException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

// list of subnets we count as "host" to determine direction of packets
struct IPv4subnet {
    pcpp::IPv4Address address;
    pcpp::IPv4Address mask;
    IPv4subnet(const pcpp::IPv4Address &a, const pcpp::IPv4Address &m)
        : address(a)
        , mask(m)
    {
    }
};
struct IPv6subnet {
    pcpp::IPv6Address address;
    uint8_t mask;
    IPv6subnet(const pcpp::IPv6Address &a, int m): address(a), mask(m) { }
};
typedef std::vector<IPv4subnet> IPv4subnetList;
typedef std::vector<IPv6subnet> IPv6subnetList;

bool IPv4tosockaddr(const pcpp::IPv4Address &ip, struct sockaddr_in *sa);
bool IPv6tosockaddr(const pcpp::IPv6Address &ip, struct sockaddr_in6 *sa);

void parseHostSpec(const std::string &spec, IPv4subnetList &ipv4List, IPv6subnetList &ipv6List);

}