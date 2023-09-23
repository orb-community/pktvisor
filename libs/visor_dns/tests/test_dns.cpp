#include <catch2/catch_all.hpp>

#include "dns.h"

using namespace visor::lib::dns;

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
        std::string static_suffix;

        domain = "biz.foo.bar.com";
        static_suffix = ".bar.com";
        result = aggregateDomain(domain, static_suffix.size());
        CHECK(result.first == ".foo.bar.com");
        CHECK(result.second == "biz.foo.bar.com");

        domain = "biz.foo.bar.com";
        static_suffix = "bar.com";
        result = aggregateDomain(domain, static_suffix.size());
        CHECK(result.first == ".foo.bar.com");
        CHECK(result.second == "biz.foo.bar.com");

        domain = "biz.foo.bar.com";
        static_suffix = "foo.bar.com";
        result = aggregateDomain(domain, static_suffix.size());
        CHECK(result.first == "biz.foo.bar.com");
        CHECK(result.second == "");

        domain = "foo.bar.com.";
        static_suffix = "biz.foo.bar.com";
        result = aggregateDomain(domain, static_suffix.size());
        CHECK(result.first == ".bar.com.");
        CHECK(result.second == "foo.bar.com.");

        domain = "www.google.co.uk";
        static_suffix = ".co.uk";
        result = aggregateDomain(domain, static_suffix.size());
        CHECK(result.first == ".google.co.uk");
        CHECK(result.second == "www.google.co.uk");

        domain = "www.google.co.uk";
        static_suffix = "google.co.uk";
        result = aggregateDomain(domain, static_suffix.size());
        CHECK(result.first == "www.google.co.uk");
        CHECK(result.second == "");
    }
}
