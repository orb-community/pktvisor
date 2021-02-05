#include "GeoDB.h"
#include <arpa/inet.h>
#include <catch2/catch.hpp>

TEST_CASE("GeoIP", "[geoip]")
{

    SECTION("Geo enablement")
    {
        CHECK(!pktvisor::geo::enabled());
        CHECK_THROWS(pktvisor::geo::GeoIP.get().enable("nonexistent.mmdb"));
        CHECK(!pktvisor::geo::enabled());
        CHECK(pktvisor::geo::GeoIP.get().getGeoLocString("2a02:dac0::") == "");
        CHECK(pktvisor::geo::GeoASN.get().getASNString("2a02:dac0::") == "");
        CHECK_NOTHROW(pktvisor::geo::GeoIP.get().enable("fixtures/GeoIP2-City-Test.mmdb"));
        CHECK(pktvisor::geo::enabled());
        CHECK_NOTHROW(pktvisor::geo::GeoASN.get().enable("fixtures/GeoIP2-ISP-Test.mmdb"));
        CHECK(pktvisor::geo::enabled());
    }

    SECTION("basic Geo lookup")
    {
        CHECK(pktvisor::geo::GeoIP.get_const().enabled());
        CHECK(pktvisor::geo::GeoIP.get().getGeoLocString("2a02:dac0::") == "EU/Russia");
        CHECK(pktvisor::geo::GeoIP.get().getGeoLocString("89.160.20.112") == "EU/Sweden/E/Linköping");
        CHECK(pktvisor::geo::GeoIP.get().getGeoLocString("216.160.83.56") == "NA/United States/WA/Milton");
    }

    SECTION("basic ASN lookup")
    {
        CHECK(pktvisor::geo::GeoASN.get_const().enabled());
        CHECK(pktvisor::geo::GeoASN.get().getASNString("1.128.0.0") == "1221/Telstra Pty Ltd");
    }

    SECTION("basic unknown")
    {
        CHECK(pktvisor::geo::GeoASN.get_const().enabled());
        CHECK(pktvisor::geo::GeoASN.get().getASNString("6.6.6.6") == "Unknown");
    }

    SECTION("basic Geo lookup, socket")
    {
        struct sockaddr_in sa4;
        sa4.sin_family = AF_INET;
        inet_pton(AF_INET, "89.160.20.112", &sa4.sin_addr.s_addr);
        CHECK(pktvisor::geo::GeoIP.get().getGeoLocString((struct sockaddr *)&sa4) == "EU/Sweden/E/Linköping");
        struct sockaddr_in6 sa6;
        sa6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, "2a02:dac0::", &sa6.sin6_addr);
        CHECK(pktvisor::geo::GeoIP.get().getGeoLocString((struct sockaddr *)&sa6) == "EU/Russia");
    }

    SECTION("basic ASN lookup, socket")
    {
        struct sockaddr_in sa4;
        sa4.sin_family = AF_INET;
        inet_pton(AF_INET, "1.128.0.0", &sa4.sin_addr.s_addr);
        CHECK(pktvisor::geo::GeoASN.get().getASNString((struct sockaddr *)&sa4) == "1221/Telstra Pty Ltd");
        struct sockaddr_in6 sa6;
        sa6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, "2401:8080::", &sa6.sin6_addr);
        CHECK(pktvisor::geo::GeoASN.get().getASNString((struct sockaddr *)&sa6) == "237/Merit Network Inc.");
    }
}
