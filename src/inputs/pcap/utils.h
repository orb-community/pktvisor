#pragma once

#include <IpAddress.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <vector>

namespace vizer::input::pcap {

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