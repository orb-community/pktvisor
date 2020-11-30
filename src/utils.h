#pragma once

#include <IpAddress.h>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>

namespace pktvisor {

// list of subnets we count as "host" to determine direction of packets
struct IPv4subnet {
    pcpp::IPv4Address address;
    pcpp::IPv4Address mask;
    IPv4subnet(const pcpp::IPv4Address &a, const pcpp::IPv4Address &m): address(a), mask(m) { }
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

template <typename Out>
void split(const std::string &s, char delim, Out result);

std::vector<std::string> split(const std::string &s, char delim);

void parseHostSpec(const std::string &spec, IPv4subnetList &ipv4List, IPv6subnetList &ipv6List);

typedef std::pair<std::string_view, std::string_view> AggDomainResult;
AggDomainResult aggregateDomain(const std::string& domain);

}