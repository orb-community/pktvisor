#include <catch2/catch.hpp>
#include "geoip.h"

TEST_CASE("GeoIP", "[geoip]")
{

    SECTION("basic Geo lookup")
    {

        pktvisor::GeoDB db("fixtures/GeoIP2-City-test.mmdb");
        CHECK(db.getGeoLocString("2a02:dac0::") == "EU/Russia");
        CHECK(db.getGeoLocString("89.160.20.112") == "EU/Sweden/E/Linköping");
        CHECK(db.getGeoLocString("216.160.83.56") == "NA/United States/WA/Milton");

    }

    SECTION("basic ASN lookup")
    {

        pktvisor::GeoDB db("fixtures/GeoIP2-ISP-test.mmdb");
        CHECK(db.getASNString("1.128.0.0") == "1221/Telstra Pty Ltd");

    }

}

