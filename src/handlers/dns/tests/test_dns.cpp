#include <ProtocolType.h>
#include <catch2/catch.hpp>
#include <sstream>

#include "dns.h"
#include "metrics.h"

TEST_CASE("dns", "[dns]")
{

    SECTION("random qnames")
    {
        pktvisor::MetricsMgr mm(false, 5, 100);
        mm.setInitialShiftTS();

        for (int i = 0; i < 9; i++) {
            for (int k = 0; k < 11; k++) {
                pktvisor::DnsLayer dns;
                dns.getDnsHeader()->queryOrResponse = pktvisor::query;
                std::stringstream name;
                name << "0000" << k << ".0000" << i << ".com";
                dns.addQuery(name.str(), pktvisor::DnsType::DNS_TYPE_A, pktvisor::DnsClass::DNS_CLASS_IN);
                mm.newDNSPacket(&dns, pktvisor::Direction::toHost, pcpp::IPv4, pcpp::UDP);
            }
        }
    }

    SECTION("aggregateDomain")
    {
        pktvisor::AggDomainResult result;
        std::string domain;

        domain = "biz.foo.bar.com";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == ".bar.com");
        CHECK(result.second == ".foo.bar.com");

        domain = "a.com";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == "a.com");
        CHECK(result.second == "");

        domain = "abcdefg.com.";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == "abcdefg.com.");
        CHECK(result.second == "");

        domain = "foo.bar.com";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == ".bar.com");
        CHECK(result.second == "foo.bar.com");

        domain = ".";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == ".");
        CHECK(result.second == "");

        domain = "..";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == "..");
        CHECK(result.second == "");

        domain = "a";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == "a");
        CHECK(result.second == "");

        domain = "a.";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == "a.");
        CHECK(result.second == "");

        domain = "foo.bar.com.";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == ".bar.com.");
        CHECK(result.second == "foo.bar.com.");

        domain = ".foo.bar.com";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == ".bar.com");
        CHECK(result.second == ".foo.bar.com");

        domain = "a.b.c";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == ".b.c");
        CHECK(result.second == "a.b.c");

        domain = ".b.c";
        result = pktvisor::aggregateDomain(domain);
        CHECK(result.first == ".b.c");
        CHECK(result.second == "");
    }
}
