#include "GeoDB.h"
#include <arpa/inet.h>
#include <catch2/catch.hpp>
#pragma GCC diagnostic ignored "-Wold-style-cast"

TEST_CASE("GeoIP", "[geoip]")
{
    SECTION("Geo enablement")
    {
        CHECK(!visor::geo::GeoIP().enabled());
        CHECK_THROWS(visor::geo::GeoIP().enable("nonexistent.mmdb"));
        CHECK(!visor::geo::GeoIP().enabled());
        CHECK(visor::geo::GeoIP().getGeoLocString("2a02:dac0::") == "");
        CHECK(visor::geo::GeoASN().getASNString("2a02:dac0::") == "");
        CHECK_NOTHROW(visor::geo::GeoIP().enable("tests/fixtures/GeoIP2-City-Test.mmdb"));
        CHECK(visor::geo::GeoIP().enabled());
        CHECK_NOTHROW(visor::geo::GeoASN().enable("tests/fixtures/GeoIP2-ISP-Test.mmdb"));
        CHECK(visor::geo::GeoASN().enabled());
    }

    SECTION("basic Geo lookup")
    {
        CHECK(visor::geo::GeoIP().enabled());
        CHECK(visor::geo::GeoIP().getGeoLocString("2a02:dac0::") == "EU/Russia");
        CHECK(visor::geo::GeoIP().getGeoLocString("89.160.20.112") == "EU/Sweden/E/Linköping");
        CHECK(visor::geo::GeoIP().getGeoLocString("216.160.83.56") == "NA/United States/WA/Milton");
    }

    SECTION("basic ASN lookup")
    {
        CHECK(visor::geo::GeoASN().enabled());
        CHECK(visor::geo::GeoASN().getASNString("1.128.0.0") == "1221/Telstra Pty Ltd");
    }

    SECTION("basic unknown")
    {
        CHECK(visor::geo::GeoASN().enabled());
        CHECK(visor::geo::GeoASN().getASNString("6.6.6.6") == "Unknown");
    }

    SECTION("basic Geo lookup, socket")
    {
        struct sockaddr_in sa4;
        sa4.sin_family = AF_INET;
        inet_pton(AF_INET, "89.160.20.112", &sa4.sin_addr.s_addr);
        CHECK(visor::geo::GeoIP().getGeoLocString(&sa4) == "EU/Sweden/E/Linköping");
        CHECK(visor::geo::GeoIP().getGeoLocString(&sa4) == "EU/Sweden/E/Linköping");
        CHECK(visor::geo::GeoIP().getGeoLocString((struct sockaddr *)&sa4) == "EU/Sweden/E/Linköping");
        struct sockaddr_in6 sa6;
        sa6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, "2a02:dac0::", &sa6.sin6_addr);
        CHECK(visor::geo::GeoIP().getGeoLocString(&sa6) == "EU/Russia");
        CHECK(visor::geo::GeoIP().getGeoLocString(&sa6) == "EU/Russia");
        CHECK(visor::geo::GeoIP().getGeoLocString((struct sockaddr *)&sa6) == "EU/Russia");
    }

    SECTION("basic ASN lookup, socket")
    {
        struct sockaddr_in sa4;
        sa4.sin_family = AF_INET;
        inet_pton(AF_INET, "1.128.0.0", &sa4.sin_addr.s_addr);
        CHECK(visor::geo::GeoASN().getASNString(&sa4) == "1221/Telstra Pty Ltd");
        CHECK(visor::geo::GeoASN().getASNString(&sa4) == "1221/Telstra Pty Ltd");
        CHECK(visor::geo::GeoASN().getASNString((struct sockaddr *)&sa4) == "1221/Telstra Pty Ltd");
        struct sockaddr_in6 sa6;
        sa6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, "2401:8080::", &sa6.sin6_addr);
        CHECK(visor::geo::GeoASN().getASNString(&sa6) == "237/Merit Network Inc.");
        CHECK(visor::geo::GeoASN().getASNString(&sa6) == "237/Merit Network Inc.");
        CHECK(visor::geo::GeoASN().getASNString((struct sockaddr *)&sa6) == "237/Merit Network Inc.");
    }
}

TEST_CASE("GeoIP without cache", "[geoip]")
{
    SECTION("Geo enablement")
    {
        CHECK_NOTHROW(visor::geo::GeoIP().enable("tests/fixtures/GeoIP2-City-Test.mmdb", 0));
        CHECK(visor::geo::GeoIP().enabled());
        CHECK_NOTHROW(visor::geo::GeoASN().enable("tests/fixtures/GeoIP2-ISP-Test.mmdb", 0));
        CHECK(visor::geo::GeoASN().enabled());
    }

    SECTION("basic Geo lookup")
    {
        CHECK(visor::geo::GeoIP().enabled());
        CHECK(visor::geo::GeoIP().getGeoLocString("2a02:dac0::") == "EU/Russia");
    }

    SECTION("basic ASN lookup")
    {
        CHECK(visor::geo::GeoASN().enabled());
        CHECK(visor::geo::GeoASN().getASNString("1.128.0.0") == "1221/Telstra Pty Ltd");
    }

    SECTION("basic unknown")
    {
        CHECK(visor::geo::GeoASN().enabled());
        CHECK(visor::geo::GeoASN().getASNString("6.6.6.6") == "Unknown");
    }

    SECTION("basic Geo lookup, socket")
    {
        struct sockaddr_in sa4;
        sa4.sin_family = AF_INET;
        inet_pton(AF_INET, "89.160.20.112", &sa4.sin_addr.s_addr);
        CHECK(visor::geo::GeoIP().getGeoLocString(&sa4) == "EU/Sweden/E/Linköping");
        struct sockaddr_in6 sa6;
        sa6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, "2a02:dac0::", &sa6.sin6_addr);
        CHECK(visor::geo::GeoIP().getGeoLocString(&sa6) == "EU/Russia");
    }

    SECTION("basic ASN lookup, socket")
    {
        struct sockaddr_in sa4;
        sa4.sin_family = AF_INET;
        inet_pton(AF_INET, "1.128.0.0", &sa4.sin_addr.s_addr);
        CHECK(visor::geo::GeoASN().getASNString(&sa4) == "1221/Telstra Pty Ltd");
        struct sockaddr_in6 sa6;
        sa6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, "2401:8080::", &sa6.sin6_addr);
        CHECK(visor::geo::GeoASN().getASNString(&sa6) == "237/Merit Network Inc.");
    }
}
