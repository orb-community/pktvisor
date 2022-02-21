#include <catch2/catch.hpp>

#include "DnsStreamHandler.h"
#include "DnstapInputStream.h"

using namespace visor::handler::dns;
using namespace visor::input::pcap;
using namespace nlohmann;

TEST_CASE("Parse DNSTAP", "[dnstap][dns]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");
    stream.config_set<visor::Configurable::StringList>("only_hosts", {"192.168.0.0/24", "2001:db8::/48"});
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
    CHECK(counters.TCP.value() == 0);
    CHECK(counters.UDP.value() == 153);
    CHECK(counters.IPv4.value() == 153);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.queries.value() == 79);
    CHECK(counters.replies.value() == 74);
    CHECK(counters.xacts_total.value() == 0);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 0);
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.NOERROR.value() == 0);
    CHECK(counters.NX.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.SRVFAIL.value() == 0);
    CHECK(counters.filtered.value() == 0);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cardinality"]["qname"] == 70);

    CHECK(j["top_qname2"][0]["name"] == ".google.com");
    CHECK(j["top_qname2"][0]["estimate"] == 18);

    CHECK(j["top_udp_ports"][0]["name"] == "33000");
    CHECK(j["top_udp_ports"][0]["estimate"] == 4);

    CHECK(j["top_qtype"][0]["name"] == "A");
    CHECK(j["top_qtype"][0]["estimate"] == 149);
    CHECK(j["top_qtype"][1]["name"] == "HTTPS");
    CHECK(j["top_qtype"][1]["estimate"] == 4);
}

TEST_CASE("Parse filtered DNSTAP empty data", "[dnstap][dns][filter]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", &stream, &c};

    dns_handler.config_set<std::string>("dnstap_msg_type", "auth");

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 153);
    CHECK(event_data.num_samples->value() == 153);
    CHECK(counters.TCP.value() == 0);
    CHECK(counters.UDP.value() == 0);
    CHECK(counters.IPv4.value() == 0);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.queries.value() == 0);
    CHECK(counters.replies.value() == 0);
    CHECK(counters.xacts_total.value() == 0);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 0);
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.NOERROR.value() == 0);
    CHECK(counters.NX.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.SRVFAIL.value() == 0);
    CHECK(counters.filtered.value() == 153);
}

TEST_CASE("Parse filtered DNSTAP with data", "[dnstap][dns][filter]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", &stream, &c};

    dns_handler.config_set<std::string>("dnstap_msg_type", "client");

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 153);
    CHECK(event_data.num_samples->value() == 153);
    CHECK(counters.TCP.value() == 0);
    CHECK(counters.UDP.value() == 153);
    CHECK(counters.IPv4.value() == 153);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.queries.value() == 79);
    CHECK(counters.replies.value() == 74);
    CHECK(counters.xacts_total.value() == 0);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 0);
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.NOERROR.value() == 0);
    CHECK(counters.NX.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.SRVFAIL.value() == 0);
    CHECK(counters.filtered.value() == 0);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cardinality"]["qname"] == 70);

    CHECK(j["top_qname2"][0]["name"] == ".google.com");
    CHECK(j["top_qname2"][0]["estimate"] == 18);

    CHECK(j["top_udp_ports"][0]["name"] == "33000");
    CHECK(j["top_udp_ports"][0]["estimate"] == 4);

    CHECK(j["top_qtype"][0]["name"] == "A");
    CHECK(j["top_qtype"][0]["estimate"] == 149);
    CHECK(j["top_qtype"][1]["name"] == "HTTPS");
    CHECK(j["top_qtype"][1]["estimate"] == 4);
}

TEST_CASE("Invalid DNSTAP filter", "[dnstap][dns][filter]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", &stream, &c};

    dns_handler.config_set<std::string>("dnstap_msg_type", "sender");
    REQUIRE_THROWS_WITH(dns_handler.start(), "dnstap_msg_type contained an invalid/unsupported type. Valid types: auth, client, forwarder, resolver, stub, tool, update");
}
