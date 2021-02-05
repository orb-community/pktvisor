#include "GeoDB.h"
#include <catch2/catch.hpp>

TEST_CASE("GeoIP", "[geoip]")
{

    SECTION("Geo enable")
    {
        CHECK_THROWS(pktvisor::geo::GeoIP.get().enable("nonexistent.mmdb"));
        CHECK_NOTHROW(pktvisor::geo::GeoIP.get().enable("fixtures/GeoIP2-City-Test.mmdb"));
        CHECK_NOTHROW(pktvisor::geo::GeoASN.get().enable("fixtures/GeoIP2-ISP-Test.mmdb"));
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
}
