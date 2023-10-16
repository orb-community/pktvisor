#include <catch2/catch_test_macros.hpp>

#include "dns.h"

using namespace visor::lib::dns;

static std::pair<std::string, std::string> convert(const AggDomainResult &result)
{
    return {std::string(result.first), std::string(result.second)};
}

TEST_CASE("DNS Utilities", "[dns]")
{
    std::pair<std::string, std::string> result;
    std::string domain;

    SECTION("aggregateDomain")
    {
        domain = "biz.foo.bar.com";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == ".bar.com");
        CHECK(result.second == ".foo.bar.com");

        domain = "a.com";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == "a.com");
        CHECK(result.second == "");

        domain = "abcdefg.com.";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == "abcdefg.com.");
        CHECK(result.second == "");

        domain = "foo.bar.com";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == ".bar.com");
        CHECK(result.second == "foo.bar.com");

        domain = ".";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == ".");
        CHECK(result.second == "");

        domain = "..";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == "..");
        CHECK(result.second == "");

        domain = "a";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == "a");
        CHECK(result.second == "");

        domain = "a.";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == "a.");
        CHECK(result.second == "");

        domain = "foo.bar.com.";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == ".bar.com.");
        CHECK(result.second == "foo.bar.com.");

        domain = ".foo.bar.com";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == ".bar.com");
        CHECK(result.second == ".foo.bar.com");

        domain = "a.b.c";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == ".b.c");
        CHECK(result.second == "a.b.c");

        domain = ".b.c";
        result = convert(aggregateDomain(domain));
        CHECK(result.first == ".b.c");
        CHECK(result.second == "");
    }

    SECTION("aggregateDomain with static suffix")
    {
        std::string static_suffix;

        domain = "biz.foo.bar.com";
        static_suffix = ".bar.com";
        result = convert(aggregateDomain(domain, static_suffix.size()));
        CHECK(result.first == ".foo.bar.com");
        CHECK(result.second == "biz.foo.bar.com");

        domain = "biz.foo.bar.com";
        static_suffix = "bar.com";
        result = convert(aggregateDomain(domain, static_suffix.size()));
        CHECK(result.first == ".foo.bar.com");
        CHECK(result.second == "biz.foo.bar.com");

        domain = "biz.foo.bar.com";
        static_suffix = "foo.bar.com";
        result = convert(aggregateDomain(domain, static_suffix.size()));
        CHECK(result.first == "biz.foo.bar.com");
        CHECK(result.second == "");

        domain = "foo.bar.com.";
        static_suffix = "biz.foo.bar.com";
        result = convert(aggregateDomain(domain, static_suffix.size()));
        CHECK(result.first == ".bar.com.");
        CHECK(result.second == "foo.bar.com.");

        domain = "www.google.co.uk";
        static_suffix = ".co.uk";
        result = convert(aggregateDomain(domain, static_suffix.size()));
        CHECK(result.first == ".google.co.uk");
        CHECK(result.second == "www.google.co.uk");

        domain = "www.google.co.uk";
        static_suffix = "google.co.uk";
        result = convert(aggregateDomain(domain, static_suffix.size()));
        CHECK(result.first == "www.google.co.uk");
        CHECK(result.second == "");
    }
}
