#include <catch2/catch.hpp>

#include "DnsStreamHandler.h"
#include "DnstapInputStream.h"

using namespace visor::handler::dns;
using namespace visor::input::pcap;
using namespace nlohmann;

TEST_CASE("Parse DNSTAP", "[dnstap][net]")
{

    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", &stream, &c};

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 153);
    CHECK(event_data.num_samples->value() == 153);
    CHECK(counters.TCP.value() == 2880);
    CHECK(counters.UDP.value() == 2971);
    CHECK(counters.IPv4.value() == 5851);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.queries.value() == 2930);
    CHECK(counters.replies.value() == 2921);
    CHECK(counters.xacts_total.value() == 2921);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 2921);
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.NOERROR.value() == 2921);
    CHECK(counters.NOERROR.value() == 2921);
    CHECK(counters.NX.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.SRVFAIL.value() == 0);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cardinality"]["qname"] == 2055); // flame was run with 1000 randoms x2 (udp+tcp)

    CHECK(j["top_qname2"][0]["name"] == ".test.com");
    CHECK(j["top_qname2"][0]["estimate"] == event_data.num_events->value());

    CHECK(j["top_rcode"][0]["name"] == "NOERROR");
    CHECK(j["top_rcode"][0]["estimate"] == counters.NOERROR.value());

    CHECK(j["top_udp_ports"][0]["name"] == "57975");
    CHECK(j["top_udp_ports"][0]["estimate"] == 302);

    CHECK(j["top_qtype"][0]["name"] == "AAAA");
    CHECK(j["top_qtype"][0]["estimate"] == 1476);
    CHECK(j["top_qtype"][1]["name"] == "CNAME");
    CHECK(j["top_qtype"][1]["estimate"] == 825);
    CHECK(j["top_qtype"][2]["name"] == "SOA");
    CHECK(j["top_qtype"][2]["estimate"] == 794);
    CHECK(j["top_qtype"][3]["name"] == "MX");
    CHECK(j["top_qtype"][3]["estimate"] == 757);
    CHECK(j["top_qtype"][4]["name"] == "A");
    CHECK(j["top_qtype"][4]["estimate"] == 717);
    CHECK(j["top_qtype"][5]["name"] == "NS");
    CHECK(j["top_qtype"][5]["estimate"] == 662);
    CHECK(j["top_qtype"][6]["name"] == "TXT");
    CHECK(j["top_qtype"][6]["estimate"] == 620);
}

