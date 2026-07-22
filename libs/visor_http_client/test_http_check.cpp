#include "HttpCheck.h"
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <curl/curl.h>
#include <utility>

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

TEST_CASE("JsonPointerCheck", "[http][check]")
{
    auto eq = JsonPointerCheck::compile("/data/status", "ok", true);
    CHECK(eq.configured());
    CHECK(eq.matches(R"({"data":{"status":"ok"}})"));
    CHECK_FALSE(eq.matches(R"({"data":{"status":"down"}})"));
    CHECK_FALSE(eq.matches(R"({"data":{}})"));           // pointer doesn't resolve
    CHECK_FALSE(eq.matches("not json"));                  // parse failure

    // number/bool compared by compact JSON text
    CHECK(JsonPointerCheck::compile("/code", "200", true).matches(R"({"code":200})"));
    CHECK(JsonPointerCheck::compile("/ok", "true", true).matches(R"({"ok":true})"));

    // presence-only (no equals)
    auto present = JsonPointerCheck::compile("/data/status", "", false);
    CHECK(present.matches(R"({"data":{"status":"anything"}})"));
    CHECK_FALSE(present.matches(R"({"data":{}})"));

    CHECK_FALSE(JsonPointerCheck{}.configured());
    CHECK_THROWS_AS(JsonPointerCheck::compile("data/status", "", false), std::invalid_argument); // no leading '/'
}

TEST_CASE("BodyNegativeCheck", "[http][check]")
{
    auto n = BodyNegativeCheck::compile("traceback", "ERROR|FATAL");
    CHECK(n.configured());
    CHECK(n.matches("all good"));
    CHECK_FALSE(n.matches("python traceback (most recent call last)"));
    CHECK_FALSE(n.matches("status: FATAL"));
    CHECK_FALSE(BodyNegativeCheck::compile("", "").configured());
    CHECK_THROWS_AS(BodyNegativeCheck::compile("", "(unclosed"), std::invalid_argument);
}

TEST_CASE("HeaderMatchers", "[http][check]")
{
    std::vector<std::pair<std::string,std::string>> hdrs = {
        {"Content-Type", "application/json"}, {"X-Cache", "HIT"}};
    // fail_if_matches: X-Debug present with any value -> here absent -> PASS
    CHECK(HeaderMatchers::compile({{"X-Debug", ".+"}}, {}).matches(hdrs));
    // fail_if_matches: X-Cache matches HIT -> FAIL
    CHECK_FALSE(HeaderMatchers::compile({{"X-Cache", "HIT"}}, {}).matches(hdrs));
    // fail_if_not_matches: Content-Type must match application/json -> present -> PASS
    CHECK(HeaderMatchers::compile({}, {{"content-type", "application/json"}}).matches(hdrs)); // case-insensitive name
    // fail_if_not_matches: requires an X-Missing match -> absent -> FAIL
    CHECK_FALSE(HeaderMatchers::compile({}, {{"X-Missing", ".+"}}).matches(hdrs));
    CHECK_FALSE(HeaderMatchers::compile({}, {}).configured());
    CHECK_THROWS_AS(HeaderMatchers::compile({{"X", "(bad"}}, {}), std::invalid_argument);
    // has_forbidden_rules(): true only when a fail_if_matches rule exists (drives the probe's
    // truncation fail-safe — a required-only config must not fail-safe on truncation).
    CHECK(HeaderMatchers::compile({{"X-Debug", ".+"}}, {}).has_forbidden_rules());
    CHECK(HeaderMatchers::compile({{"X-Debug", ".+"}}, {{"X-Ok", "1"}}).has_forbidden_rules());
    CHECK_FALSE(HeaderMatchers::compile({}, {{"X-Ok", "1"}}).has_forbidden_rules());
    CHECK_FALSE(HeaderMatchers::compile({}, {}).has_forbidden_rules());
}

TEST_CASE("parse_http_date + http_version_name", "[http][check]")
{
    CHECK(parse_http_date("Wed, 21 Oct 2026 07:28:00 GMT") != 0);
    CHECK(parse_http_date("") == 0);
    CHECK(parse_http_date("garbage") == 0);
    CHECK(http_version_name(CURL_HTTP_VERSION_1_1) == "1.1");
    CHECK(http_version_name(CURL_HTTP_VERSION_2_0) == "2");
    CHECK(http_version_name(CURL_HTTP_VERSION_3) == "3");
    CHECK(http_version_name(0) == "");
}
