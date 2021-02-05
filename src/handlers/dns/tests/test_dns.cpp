#include <ProtocolType.h>
#include <catch2/catch.hpp>
#include <sstream>

#include "dns.h"

using namespace pktvisor::handler::dns;

TEST_CASE("dns", "[dns]")
{

    // TODO replace with pcap integration test
    //    SECTION("random qnames")
    //    {
    //        MetricsMgr mm(false, 5, 100);
    //        mm.setInitialShiftTS();
    //
    //        for (int i = 0; i < 9; i++) {
    //            for (int k = 0; k < 11; k++) {
    //                DnsLayer dns;
    //                dns.getDnsHeader()->queryOrResponse = query;
    //                std::stringstream name;
    //                name << "0000" << k << ".0000" << i << ".com";
    //                dns.addQuery(name.str(), DnsType::DNS_TYPE_A, DnsClass::DNS_CLASS_IN);
    //                mm.newDNSPacket(&dns, Direction::toHost, pcpp::IPv4, pcpp::UDP);
    //            }
    //        }
    //    }

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
}
