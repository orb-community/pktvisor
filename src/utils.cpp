
#include "utils.h"
#include <cstring>
#include <sstream>
#ifdef __linux__
#include <in.h>
#else
#include <netinet/in.h>
#endif
#include <arpa/inet.h>
#include <IpUtils.h>

namespace pktvisor {

AggDomainResult aggregateDomain(const std::string& domain) {

    std::string_view qname2(domain);
    std::string_view qname3(domain);

    // smallest we ever agg is a.b.c which returns a.b.c and b.c
    if (domain.size() < 5) {
        qname3.remove_prefix(domain.size());
        return AggDomainResult(qname2, qname3);
    }
    std::size_t endDot = std::string::npos;
    if (domain.back() == '.') {
        endDot = domain.size() - 2;
    }
    auto first_dot = domain.rfind('.', endDot);
    if (first_dot != std::string::npos && first_dot > 0) {
        auto second_dot = domain.rfind('.', first_dot - 1);
        if (second_dot != std::string::npos) {
            qname2.remove_prefix(second_dot);
            if (second_dot > 0) {
                auto third_dot = domain.rfind('.', second_dot - 1);
                if (third_dot != std::string::npos) {
                    qname3.remove_prefix(third_dot);
                }
            }
        }
        else {
            // didn't find two dots, so this is empty
            qname3.remove_prefix(domain.size());
        }
    }
    return AggDomainResult(qname2, qname3);
}

template <typename Out>
void split(const std::string &s, char delim, Out result)
{
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}

std::vector<std::string> split(const std::string &s, char delim)
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
#ifdef __linux__
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
            if (inet_ntop(AF_INET6, &mask_addr, buf, INET6_ADDRSTRLEN) == 0) {
                std::stringstream err;
                err << "invalid IPv6 address mask: " << cidr[1];
                throw std::runtime_error(err.str());
            }
            ipv6List.emplace_back(pktvisor::IPv6subnet(net, pcpp::IPv6Address(buf)));
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
            if (inet_ntop(AF_INET, &mask_addr, buf, INET_ADDRSTRLEN) == 0) {
                std::stringstream err;
                err << "invalid IPv4 address mask: " << cidr[1];
                throw std::runtime_error(err.str());
            }
            ipv4List.emplace_back(pktvisor::IPv4subnet(net, pcpp::IPv4Address(buf)));
        }
    }
}

}
