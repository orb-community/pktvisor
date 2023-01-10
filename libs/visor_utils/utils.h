/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef _WIN32
#include <Ws2tcpip.h>
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif
#include <IpAddress.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace visor::lib::utils {

class UtilsException : public std::runtime_error
{
public:
    UtilsException(const char *msg)
        : std::runtime_error(msg)
    {
    }
    UtilsException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

// list of subnets we count as "host" to determine direction of packets
struct IPv4subnet {
    in_addr addr;
    uint8_t cidr;
    std::string str;
};

struct IPv6subnet {
    in6_addr addr;
    uint8_t cidr;
    std::string str;
};
typedef std::vector<IPv4subnet> IPv4subnetList;
typedef std::vector<IPv6subnet> IPv6subnetList;

bool ipv4_to_sockaddr(const pcpp::IPv4Address &ip, struct sockaddr_in *sa);
bool ipv6_to_sockaddr(const pcpp::IPv6Address &ip, struct sockaddr_in6 *sa);

std::vector<std::string> split_str_to_vec_str(const std::string &spec, const char &delimiter);
void parse_host_specs(const std::vector<std::string> &host_list, IPv4subnetList &ipv4_list, IPv6subnetList &ipv6_list);
std::optional<IPv4subnetList::const_iterator> match_subnet(IPv4subnetList &ipv4_list, uint32_t ipv4_val);
std::optional<IPv6subnetList::const_iterator> match_subnet(IPv6subnetList &ipv6_list, const uint8_t *ipv6_val);
bool match_subnet(IPv4subnetList &ipv4_list, IPv6subnetList &ipv6_list, const std::string &ip_val);
}