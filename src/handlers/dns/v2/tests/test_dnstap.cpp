#include <catch2/catch.hpp>

#include "DnsStreamHandler.h"
#include "DnstapInputStream.h"

using namespace visor::handler::dns;
using namespace visor::input::pcap;
using namespace nlohmann;

TEST_CASE("Parse DNSTAP", "[dnstap][dns][!mayfail]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");
    stream.config_set<visor::Configurable::StringList>("only_hosts", {"192.168.0.0/24", "2001:db8::/48"});
    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};
    dns_handler.config_set<visor::Configurable::StringList>("enable", {"top_size", "top_ports"});

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(PacketDirection::unknown);
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 153);
    CHECK(event_data.num_samples->value() == 153);
    CHECK(counters.TCP.value() == 0);
    CHECK(counters.UDP.value() == 72);
    CHECK(counters.IPv4.value() == 72);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.xacts.value() == 72);
    CHECK(counters.timeout.value() == 0);
    CHECK(counters.RNOERROR.value() == 68);
    CHECK(counters.NX.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.SRVFAIL.value() == 4);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["undef"]["cardinality"]["qname"] == 65);

    CHECK(j["undef"]["top_qname2_xacts"][0]["name"] == ".google.com");
    CHECK(j["undef"]["top_qname2_xacts"][0]["estimate"] == 9);

    CHECK(j["undef"]["top_udp_ports_xacts"][0]["name"] == "47054");
    CHECK(j["undef"]["top_udp_ports_xacts"][0]["estimate"] == 2);

    CHECK(j["undef"]["top_qtype_xacts"][0]["name"] == "A");
    CHECK(j["undef"]["top_qtype_xacts"][0]["estimate"] == 70);
    CHECK(j["undef"]["top_qtype_xacts"][1]["name"] == "HTTPS");
    CHECK(j["undef"]["top_qtype_xacts"][1]["estimate"] == 2);
}

TEST_CASE("Parse filtered DNSTAP empty data", "[dnstap][dns][filter][!mayfail]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    dns_handler.config_set<std::string>("dnstap_msg_type", "auth");

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(PacketDirection::unknown);
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 153);
    CHECK(event_data.num_samples->value() == 153);
    CHECK(counters.TCP.value() == 0);
    CHECK(counters.UDP.value() == 0);
    CHECK(counters.IPv4.value() == 0);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.xacts.value() == 0);
    CHECK(counters.RNOERROR.value() == 0);
    CHECK(counters.NX.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.SRVFAIL.value() == 0);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);
    CHECK(j["filtered_packets"] == 153);
}

TEST_CASE("Parse filtered DNSTAP with data", "[dnstap][dns][filter][!mayfail]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};
    dns_handler.config_set<std::string>("dnstap_msg_type", "client");
    dns_handler.config_set<visor::Configurable::StringList>("enable", {"top_size", "top_ports"});

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters(PacketDirection::unknown);
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 153);
    CHECK(event_data.num_samples->value() == 153);
    CHECK(counters.TCP.value() == 0);
    CHECK(counters.UDP.value() == 72);
    CHECK(counters.IPv4.value() == 72);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.xacts.value() == 72);
    CHECK(counters.timeout.value() == 0);
    CHECK(counters.RNOERROR.value() == 68);
    CHECK(counters.NX.value() == 0);
    CHECK(counters.REFUSED.value() == 0);
    CHECK(counters.SRVFAIL.value() == 4);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["filtered_packets"] == 0);
    CHECK(j["undef"]["cardinality"]["qname"] == 65);

    CHECK(j["undef"]["top_qname2_xacts"][0]["name"] == ".google.com");
    CHECK(j["undef"]["top_qname2_xacts"][0]["estimate"] == 9);

    CHECK(j["undef"]["top_udp_ports_xacts"][0]["name"] == "47054");
    CHECK(j["undef"]["top_udp_ports_xacts"][0]["estimate"] == 2);

    CHECK(j["undef"]["top_qtype_xacts"][0]["name"] == "A");
    CHECK(j["undef"]["top_qtype_xacts"][0]["estimate"] == 70);
    CHECK(j["undef"]["top_qtype_xacts"][1]["name"] == "HTTPS");
    CHECK(j["undef"]["top_qtype_xacts"][1]["estimate"] == 2);
}

TEST_CASE("Invalid DNSTAP filter", "[dnstap][dns][filter]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    dns_handler.config_set<std::string>("dnstap_msg_type", "sender");
    REQUIRE_THROWS_WITH(dns_handler.start(), "DnsStreamHandler: dnstap_msg_type contained an invalid/unsupported type. Valid types: auth, client, forwarder, resolver, stub, tool, update");
}
