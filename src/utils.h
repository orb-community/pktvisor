#pragma once

#include <IpAddress.h>
#include <string>
#include <vector>

namespace pktvisor {

// list of subnets we count as "host" to determine direction of packets
typedef std::pair<pcpp::IPv4Address, pcpp::IPv4Address> IPv4subnet;
typedef std::pair<pcpp::IPv6Address, uint8_t> IPv6subnet;
typedef std::vector<IPv4subnet> IPv4subnetList;
typedef std::vector<IPv6subnet> IPv6subnetList;

template <typename Out>
void split(const std::string &s, char delim, Out result);

std::vector<std::string> split(const std::string &s, char delim);

void parseHostSpec(const std::string &spec, IPv4subnetList &ipv4List, IPv6subnetList &ipv6List);

typedef std::pair<std::string_view, std::string_view> AggDomainResult;
AggDomainResult aggregateDomain(const std::string& domain);

}