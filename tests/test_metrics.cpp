#include <ProtocolType.h>
#include <catch2/catch.hpp>
#include <sstream>

#include "metrics.h"
#include "dns/dns.h"

TEST_CASE("metrics", "[metrics]")
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
                dns.addQuery(name.str(), pcpp::DnsType::DNS_TYPE_A, pcpp::DnsClass::DNS_CLASS_IN);
                mm.newDNSPacket(&dns, pktvisor::Direction::toHost, pcpp::IPv4, pcpp::UDP);
            }
        }
    }
}
