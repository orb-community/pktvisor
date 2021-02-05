#include "utils.h"
#include <catch2/catch.hpp>
#include <netinet/in.h>

using namespace pktvisor;
using namespace pktvisor::input::pcap;

TEST_CASE("parseHostSpec", "[utils]")
{

    SECTION("IPv4 /24")
    {
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        parseHostSpec("192.168.0.0/24", hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        CHECK(hostIPv4[0].address.toString() == "192.168.0.0");
        CHECK(hostIPv4[0].mask.toString() == "255.255.255.0");
    }

    SECTION("IPv4 /23")
    {
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        parseHostSpec("192.168.1.1/23", hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        CHECK(hostIPv4[0].address.toString() == "192.168.1.1");
        CHECK(hostIPv4[0].mask.toString() == "255.255.254.0");
    }

    SECTION("IPv4 /32")
    {
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        parseHostSpec("192.168.1.5/32", hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        CHECK(hostIPv4[0].address.toString() == "192.168.1.5");
        CHECK(hostIPv4[0].mask.toString() == "255.255.255.255");
    }

    SECTION("IPv4 2 entries")
    {
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        parseHostSpec("192.168.1.5/32,192.168.1.20/32", hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 2);
        CHECK(hostIPv4[0].address.toString() == "192.168.1.5");
        CHECK(hostIPv4[0].mask.toString() == "255.255.255.255");
        CHECK(hostIPv4[1].address.toString() == "192.168.1.20");
        CHECK(hostIPv4[1].mask.toString() == "255.255.255.255");
    }

    SECTION("IPv6 /48")
    {
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        parseHostSpec("2001:7f8:1::a506:2597:1/48", hostIPv4, hostIPv6);
        CHECK(hostIPv6.size() == 1);
        CHECK(hostIPv6[0].address.toString() == "2001:7f8:1::a506:2597:1");
        CHECK(hostIPv6[0].mask == 48);
    }

    SECTION("mixed entries")
    {
        IPv4subnetList hostIPv4;
        IPv6subnetList hostIPv6;
        parseHostSpec("192.168.1.5/32,2001:7f8:1::a506:2597:1/48", hostIPv4, hostIPv6);
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
        CHECK(IPv4tosockaddr(ip, &sa));
        CHECK(memcmp(&sa.sin_addr, &ip_int, sizeof(sa.sin_addr)) == 0);
        CHECK(sa.sin_family == AF_INET);
    }
}

