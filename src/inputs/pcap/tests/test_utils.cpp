#include "utils.h"
#include <catch2/catch.hpp>
#include <netinet/in.h>

TEST_CASE("parseHostSpec", "[utils]")
{

    SECTION("basic Geo lookup")
    {

        pcpp::IPv4Address ip("89.160.20.112");
        struct sockaddr_in sa4;
        CHECK(pktvisor::IPv4tosockaddr(ip, &sa4));
        CHECK(db.getGeoLocString((struct sockaddr *)&sa4) == "EU/Sweden/E/Linköping");
        pcpp::IPv6Address ip6("2a02:dac0::");
        struct sockaddr_in6 sa6;
        CHECK(pktvisor::IPv6tosockaddr(ip6, &sa6));
        CHECK(db.getGeoLocString((struct sockaddr *)&sa6) == "EU/Russia");
    }

    SECTION("basic ASN lookup")
    {

        pcpp::IPv4Address ip("1.128.0.0");
        struct sockaddr_in sa4;
        CHECK(pktvisor::IPv4tosockaddr(ip, &sa4));
        CHECK(db.getASNString((struct sockaddr *)&sa4) == "1221/Telstra Pty Ltd");
        pcpp::IPv6Address ip6("2401:8080::");
        struct sockaddr_in6 sa6;
        CHECK(pktvisor::IPv6tosockaddr(ip6, &sa6));
        CHECK(db.getASNString((struct sockaddr *)&sa6) == "237/Merit Network Inc.");
    }

    SECTION("IPv4 /24")
    {
        pktvisor::IPv4subnetList hostIPv4;
        pktvisor::IPv6subnetList hostIPv6;
        pktvisor::parseHostSpec("192.168.0.0/24", hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        CHECK(hostIPv4[0].address.toString() == "192.168.0.0");
        CHECK(hostIPv4[0].mask.toString() == "255.255.255.0");
    }

    SECTION("IPv4 /23")
    {
        pktvisor::IPv4subnetList hostIPv4;
        pktvisor::IPv6subnetList hostIPv6;
        pktvisor::parseHostSpec("192.168.1.1/23", hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        CHECK(hostIPv4[0].address.toString() == "192.168.1.1");
        CHECK(hostIPv4[0].mask.toString() == "255.255.254.0");
    }

    SECTION("IPv4 /32")
    {
        pktvisor::IPv4subnetList hostIPv4;
        pktvisor::IPv6subnetList hostIPv6;
        pktvisor::parseHostSpec("192.168.1.5/32", hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        CHECK(hostIPv4[0].address.toString() == "192.168.1.5");
        CHECK(hostIPv4[0].mask.toString() == "255.255.255.255");
    }

    SECTION("IPv4 2 entries")
    {
        pktvisor::IPv4subnetList hostIPv4;
        pktvisor::IPv6subnetList hostIPv6;
        pktvisor::parseHostSpec("192.168.1.5/32,192.168.1.20/32", hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 2);
        CHECK(hostIPv4[0].address.toString() == "192.168.1.5");
        CHECK(hostIPv4[0].mask.toString() == "255.255.255.255");
        CHECK(hostIPv4[1].address.toString() == "192.168.1.20");
        CHECK(hostIPv4[1].mask.toString() == "255.255.255.255");
    }

    SECTION("IPv6 /48")
    {
        pktvisor::IPv4subnetList hostIPv4;
        pktvisor::IPv6subnetList hostIPv6;
        pktvisor::parseHostSpec("2001:7f8:1::a506:2597:1/48", hostIPv4, hostIPv6);
        CHECK(hostIPv6.size() == 1);
        CHECK(hostIPv6[0].address.toString() == "2001:7f8:1::a506:2597:1");
        CHECK(hostIPv6[0].mask == 48);
    }

    SECTION("mixed entries")
    {
        pktvisor::IPv4subnetList hostIPv4;
        pktvisor::IPv6subnetList hostIPv6;
        pktvisor::parseHostSpec("192.168.1.5/32,2001:7f8:1::a506:2597:1/48", hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        CHECK(hostIPv6.size() == 1);
        CHECK(hostIPv4[0].address.toString() == "192.168.1.5");
        CHECK(hostIPv4[0].mask.toString() == "255.255.255.255");
        CHECK(hostIPv6[0].address.toString() == "2001:7f8:1::a506:2597:1");
        CHECK(hostIPv6[0].mask == 48);
    }

    SECTION("ip format conversion")
    {
        pcpp::IPv4Address ip("1.128.0.0");
        uint32_t ip_int(ip.toInt());
        struct sockaddr_in sa;
        CHECK(pktvisor::IPv4tosockaddr(ip, &sa));
        CHECK(memcmp(&sa.sin_addr, &ip_int, sizeof(sa.sin_addr)) == 0);
        CHECK(sa.sin_family == AF_INET);
    }

}

