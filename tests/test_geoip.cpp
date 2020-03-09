#include <catch2/catch.hpp>
#include <IpAddress.h>
#include "geoip.h"

TEST_CASE("GeoIP", "[geoip]")
{

    SECTION("basic Geo lookup")
    {

        pktvisor::GeoDB db("fixtures/GeoIP2-City-Test.mmdb");
        CHECK(db.getGeoLocString("2a02:dac0::") == "EU/Russia");
        CHECK(db.getGeoLocString("89.160.20.112") == "EU/Sweden/E/Linköping");
        CHECK(db.getGeoLocString("216.160.83.56") == "NA/United States/WA/Milton");

    }

    SECTION("basic ASN lookup")
    {

        pktvisor::GeoDB db("fixtures/GeoIP2-ISP-Test.mmdb");
        CHECK(db.getASNString("1.128.0.0") == "1221/Telstra Pty Ltd");

    }

    SECTION("basic Geo lookup: sockaddr")
    {

        pktvisor::GeoDB db("fixtures/GeoIP2-City-Test.mmdb");
        pcpp::IPv4Address ip("89.160.20.112");
        CHECK(db.getGeoLocString(ip.toInAddr()) == "EU/Sweden/E/Linköping");
        pcpp::IPv6Address ip6("2a02:dac0::");
        CHECK(db.getGeoLocString(ip6.toIn6Addr()) == "EU/Russia");

    }

    SECTION("basic ASN lookup: sockaddr")
    {

        pktvisor::GeoDB db("fixtures/GeoIP2-ISP-Test.mmdb");
        pcpp::IPv4Address ip("1.128.0.0");
        CHECK(db.getASNString(ip.toInAddr()) == "1221/Telstra Pty Ltd");
        pcpp::IPv6Address ip6("2401:8080::");
        CHECK(db.getASNString(ip6.toIn6Addr()) == "237/Merit Network Inc.");

    }

    SECTION("basic unknown")
    {

        pktvisor::GeoDB db("fixtures/GeoIP2-ISP-Test.mmdb");
        CHECK(db.getASNString("6.6.6.6") == "Unknown");

    }

    SECTION("bad GeoDB")
    {

        CHECK_THROWS_WITH(pktvisor::GeoDB("nonexistantfile.mmdb"),
            "nonexistantfile.mmdb: Error opening the specified MaxMind DB file");

    }

}

