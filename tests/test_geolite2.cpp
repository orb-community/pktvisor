#include <catch2/catch.hpp>
#include "GeoLite2PP.h"

TEST_CASE("GeoLite2PP", "[geo]")
{

    SECTION("basic Geo lookup")
    {
        GeoLite2PP::DB db("fixtures/ipdb.mmdb");
        uint16_t country, prov, isp, city;
        db.get_geoinfo("36.110.59.146", country, prov, isp, city);
        CHECK(country == 47);
        CHECK(isp == 1);
        CHECK(prov == 1);

        GeoLite2PP::DB db2("fixtures/GeoIP2-City-test.mmdb");
        db2.getGeoCountry("151.164.110.64");

    }


}

