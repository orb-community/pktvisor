#include "HttpCheck.h"
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

using namespace visor::http;

TEST_CASE("StatusMatcher grammar", "[http][check]")
{
    auto m = StatusMatcher::parse({"200", "2xx", "301-303", "429"});
    CHECK(m.matches(200));
    CHECK(m.matches(204)); // via 2xx
    CHECK(m.matches(302)); // via range
    CHECK(m.matches(429));
    CHECK_FALSE(m.matches(304));
    CHECK_FALSE(m.matches(500));
    CHECK_FALSE(m.empty());

    CHECK(StatusMatcher{}.empty());
    CHECK_FALSE(StatusMatcher{}.matches(200));

    CHECK_THROWS_AS(StatusMatcher::parse({"2x"}), std::invalid_argument);
    CHECK_THROWS_AS(StatusMatcher::parse({"abc"}), std::invalid_argument);
    CHECK_THROWS_AS(StatusMatcher::parse({"600"}), std::invalid_argument);
    CHECK_THROWS_AS(StatusMatcher::parse({"99"}), std::invalid_argument);
    CHECK_THROWS_AS(StatusMatcher::parse({"300-200"}), std::invalid_argument);
    CHECK_THROWS_AS(StatusMatcher::parse({"6xx"}), std::invalid_argument);
    CHECK_THROWS_AS(StatusMatcher::parse({""}), std::invalid_argument);
    // Oversized values that wrap on a narrowing cast (fit in unsigned long, exceed unsigned) must
    // be rejected, not silently accepted as the wrapped-down code (4294967496 mod 2^32 == 200).
    CHECK_THROWS_AS(StatusMatcher::parse({"4294967496"}), std::invalid_argument);
    CHECK_THROWS_AS(StatusMatcher::parse({"200-4294967496"}), std::invalid_argument);
    // the error message names the offending entry
    CHECK_THROWS_WITH(StatusMatcher::parse({"2x"}), Catch::Matchers::ContainsSubstring("2x"));
}

TEST_CASE("BodyCheck substring AND regex", "[http][check]")
{
    auto both = BodyCheck::compile("\"status\":\"ok\"", "up|healthy");
    CHECK(both.configured());
    CHECK(both.matches("{\"status\":\"ok\",\"state\":\"up\"}"));
    CHECK_FALSE(both.matches("{\"status\":\"ok\"}"));        // regex fails
    CHECK_FALSE(both.matches("healthy"));                     // substring fails

    auto sub_only = BodyCheck::compile("ok", "");
    CHECK(sub_only.matches("looks ok"));
    CHECK_FALSE(sub_only.matches("nope"));

    auto rx_only = BodyCheck::compile("", "^ready$");
    CHECK(rx_only.matches("ready"));
    CHECK_FALSE(rx_only.matches("not ready"));

    CHECK_FALSE(BodyCheck::compile("", "").configured());
    CHECK_THROWS_AS(BodyCheck::compile("", "(unclosed"), std::invalid_argument);
}

TEST_CASE("parse_cert_expire_date", "[http][check]")
{
    // date -u -j -f "%b %d %T %Y" "Aug 15 12:00:00 2026" +%s  => 1786795200 (verified macOS)
    CHECK(parse_cert_expire_date("Aug 15 12:00:00 2026 GMT") == 1786795200ULL);
    // curl CERTINFO values can carry a leading space; must parse to the same epoch.
    CHECK(parse_cert_expire_date(" Aug 15 12:00:00 2026 GMT") == 1786795200ULL);
    CHECK(parse_cert_expire_date("Jan  2 03:04:05 2027 GMT") != 0);
    CHECK(parse_cert_expire_date("not a date") == 0);
    CHECK(parse_cert_expire_date("") == 0);
}
