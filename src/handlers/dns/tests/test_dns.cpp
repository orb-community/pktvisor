#include <catch2/catch.hpp>

#include "dns.h"

using namespace visor::handler::dns;

TEST_CASE("DNS Utilities", "[dns]")
{

    SECTION("aggregateDomain")
    {
        AggDomainResult result;
        std::string domain;

        domain = "biz.foo.bar.com";
        result = aggregateDomain(domain);
        CHECK(result.first == ".bar.com");
        CHECK(result.second == ".foo.bar.com");

        domain = "a.com";
        result = aggregateDomain(domain);
        CHECK(result.first == "a.com");
        CHECK(result.second == "");

        domain = "abcdefg.com.";
        result = aggregateDomain(domain);
        CHECK(result.first == "abcdefg.com.");
        CHECK(result.second == "");

        domain = "foo.bar.com";
        result = aggregateDomain(domain);
        CHECK(result.first == ".bar.com");
        CHECK(result.second == "foo.bar.com");

        domain = ".";
        result = aggregateDomain(domain);
        CHECK(result.first == ".");
        CHECK(result.second == "");

        domain = "..";
        result = aggregateDomain(domain);
        CHECK(result.first == "..");
        CHECK(result.second == "");

        domain = "a";
        result = aggregateDomain(domain);
        CHECK(result.first == "a");
        CHECK(result.second == "");

        domain = "a.";
        result = aggregateDomain(domain);
        CHECK(result.first == "a.");
        CHECK(result.second == "");

        domain = "foo.bar.com.";
        result = aggregateDomain(domain);
        CHECK(result.first == ".bar.com.");
        CHECK(result.second == "foo.bar.com.");

        domain = ".foo.bar.com";
        result = aggregateDomain(domain);
        CHECK(result.first == ".bar.com");
        CHECK(result.second == ".foo.bar.com");

        domain = "a.b.c";
        result = aggregateDomain(domain);
        CHECK(result.first == ".b.c");
        CHECK(result.second == "a.b.c");

        domain = ".b.c";
        result = aggregateDomain(domain);
        CHECK(result.first == ".b.c");
        CHECK(result.second == "");
    }

    SECTION("aggregateDomain with static suffix")
    {
        AggDomainResult result;
        std::string domain;

        domain = "biz.foo.bar.com";
        result = aggregateDomain(domain, ".bar.com");
        CHECK(result.first == ".foo.bar.com");
        CHECK(result.second == "biz.foo.bar.com");

        domain = "biz.foo.bar.com";
        result = aggregateDomain(domain, "bar.com");
        CHECK(result.first == ".foo.bar.com");
        CHECK(result.second == "biz.foo.bar.com");

        domain = "biz.foo.bar.com";
        result = aggregateDomain(domain, "foo.bar.com");
        CHECK(result.first == "biz.foo.bar.com");
        CHECK(result.second == "");

        domain = "foo.bar.com.";
        result = aggregateDomain(domain, "biz.foo.bar.com");
        CHECK(result.first == ".bar.com.");
        CHECK(result.second == "foo.bar.com.");

    }
}
