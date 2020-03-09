#include <catch2/catch.hpp>
#include "utils.h"

TEST_CASE("parseHostSpec", "[utils]")
{

    SECTION("aggregateDomain")
    {
        pktvisor::AggDomainResult result;
        std::string domain;

        domain = "biz.foo.bar.com";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == ".bar.com");
        CHECK(result.second == ".foo.bar.com");

        domain = "a.com";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == "a.com");
        CHECK(result.second == "");

        domain = "abcdefg.com.";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == "abcdefg.com.");
        CHECK(result.second == "");

        domain = "foo.bar.com";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == ".bar.com");
        CHECK(result.second == "foo.bar.com");

        domain = ".";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == ".");
        CHECK(result.second == ".");

        domain = "..";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == "..");
        CHECK(result.second == "..");

        domain = "a";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == "a");
        CHECK(result.second == "a");

        domain = "a.";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == "a.");
        CHECK(result.second == "a.");

        domain = "foo.bar.com.";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == ".bar.com.");
        CHECK(result.second == "foo.bar.com.");

        domain = ".foo.bar.com";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == ".bar.com");
        CHECK(result.second == ".foo.bar.com");

    }

    SECTION("IPv4 /24")
    {
        pktvisor::IPv4subnetList hostIPv4;
        pktvisor::IPv6subnetList hostIPv6;
        pktvisor::parseHostSpec("192.168.0.0/24", hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        CHECK(hostIPv4[0].first.toString() == "192.168.0.0");
        CHECK(hostIPv4[0].second.toString() == "255.255.255.0");
    }

    SECTION("IPv4 /23")
    {
        pktvisor::IPv4subnetList hostIPv4;
        pktvisor::IPv6subnetList hostIPv6;
        pktvisor::parseHostSpec("192.168.1.1/23", hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        CHECK(hostIPv4[0].first.toString() == "192.168.1.1");
        CHECK(hostIPv4[0].second.toString() == "255.255.254.0");
    }

    SECTION("IPv4 /32")
    {
        pktvisor::IPv4subnetList hostIPv4;
        pktvisor::IPv6subnetList hostIPv6;
        pktvisor::parseHostSpec("192.168.1.5/32", hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        CHECK(hostIPv4[0].first.toString() == "192.168.1.5");
        CHECK(hostIPv4[0].second.toString() == "255.255.255.255");
    }

    SECTION("IPv4 2 entries")
    {
        pktvisor::IPv4subnetList hostIPv4;
        pktvisor::IPv6subnetList hostIPv6;
        pktvisor::parseHostSpec("192.168.1.5/32,192.168.1.20/32", hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 2);
        CHECK(hostIPv4[0].first.toString() == "192.168.1.5");
        CHECK(hostIPv4[0].second.toString() == "255.255.255.255");
        CHECK(hostIPv4[1].first.toString() == "192.168.1.20");
        CHECK(hostIPv4[1].second.toString() == "255.255.255.255");
    }

    SECTION("IPv6 /48")
    {
        pktvisor::IPv4subnetList hostIPv4;
        pktvisor::IPv6subnetList hostIPv6;
        pktvisor::parseHostSpec("2001:7f8:1::a506:2597:1/48", hostIPv4, hostIPv6);
        CHECK(hostIPv6.size() == 1);
        CHECK(hostIPv6[0].first.toString() == "2001:7f8:1::a506:2597:1");
        CHECK(hostIPv6[0].second.toString() == "ffff:ffff:ffff::");
    }

    SECTION("mixed entries")
    {
        pktvisor::IPv4subnetList hostIPv4;
        pktvisor::IPv6subnetList hostIPv6;
        pktvisor::parseHostSpec("192.168.1.5/32,2001:7f8:1::a506:2597:1/48", hostIPv4, hostIPv6);
        CHECK(hostIPv4.size() == 1);
        CHECK(hostIPv6.size() == 1);
        CHECK(hostIPv4[0].first.toString() == "192.168.1.5");
        CHECK(hostIPv4[0].second.toString() == "255.255.255.255");
        CHECK(hostIPv6[0].first.toString() == "2001:7f8:1::a506:2597:1");
        CHECK(hostIPv6[0].second.toString() == "ffff:ffff:ffff::");
    }

}

