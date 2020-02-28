#include <catch2/catch.hpp>
#include "GeoLite2PP.h"

TEST_CASE("GeoLite2PP", "[geo]")
{

    SECTION("basic Geo lookup")
    {

        GeoLite2PP::DB db2("fixtures/GeoIP2-City-test.mmdb");
        CHECK(db2.getGeoLocString("2a02:dac0::") == "EU/Russia");
        CHECK(db2.getGeoLocString("89.160.20.112") == "EU/Sweden/E/Linköping");
        CHECK(db2.getGeoLocString("216.160.83.56") == "NA/United States/WA/Milton");

    }

    SECTION("basic ASN lookup")
    {

        GeoLite2PP::DB db2("fixtures/GeoIP2-ISP-test.mmdb");
        CHECK(db2.getASNString("1.128.0.0") == "1221/Telstra Pty Ltd");

    }

}

