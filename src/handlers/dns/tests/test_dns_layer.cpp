#include <catch2/catch.hpp>

#include "DnsStreamHandler.h"
#include "PcapInputStream.h"

using namespace pktvisor::handler::dns;
using namespace pktvisor::input::pcap;
using namespace nlohmann;

TEST_CASE("Parse DNS UDP IPv4 tests", "[pcap][ipv4][udp][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "fixtures/dns_ipv4_udp.pcap");
    stream.config_set("bpf", "");

    DnsStreamHandler dns_handler{"dns-test", &stream, 1, 100};

    dns_handler.start();
    stream.start();
    dns_handler.stop();
    stream.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(dns_handler.metrics()->current_periods() == 1);
    CHECK(event_data.num_events == 140);
    CHECK(counters.UDP == 140);
    CHECK(counters.IPv4 == 140);
    CHECK(counters.IPv6 == 0);
    CHECK(counters.queries == 70);
    CHECK(counters.replies == 70);
    CHECK(j["top_qname2"][0]["name"] == ".test.com");
    CHECK(j["top_qname2"][0]["estimate"] == 140);
}

TEST_CASE("Parse DNS TCP IPv4 tests", "[pcap][ipv4][tcp][dns]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "fixtures/dns_ipv4_tcp.pcap");
    stream.config_set("bpf", "");

    DnsStreamHandler dns_handler{"dns-test", &stream, 1, 100};

    dns_handler.start();
    stream.start();
    dns_handler.stop();
    stream.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events == 420);
    CHECK(counters.TCP == 420);
    CHECK(counters.IPv4 == 420);
    CHECK(counters.IPv6 == 0);
    CHECK(counters.queries == 210);
    CHECK(counters.replies == 210);
    CHECK(j["top_qname2"][0]["name"] == ".test.com");
    CHECK(j["top_qname2"][0]["estimate"] == 420);
}

TEST_CASE("Parse DNS UDP IPv6 tests", "[pcap][ipv6][udp][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "fixtures/dns_ipv6_udp.pcap");
    stream.config_set("bpf", "");

    DnsStreamHandler dns_handler{"dns-test", &stream, 1, 100};

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events == 140);
    CHECK(counters.UDP == 140);
    CHECK(counters.IPv4 == 0);
    CHECK(counters.IPv6 == 140);
    CHECK(counters.queries == 70);
    CHECK(counters.replies == 70);
    CHECK(j["top_qname2"][0]["name"] == ".test.com");
    CHECK(j["top_qname2"][0]["estimate"] == 140);
}

TEST_CASE("Parse DNS TCP IPv6 tests", "[pcap][ipv6][tcp][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "fixtures/dns_ipv6_tcp.pcap");
    stream.config_set("bpf", "");

    DnsStreamHandler dns_handler{"dns-test", &stream, 1, 100};

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events == 360);
    CHECK(counters.TCP == 360);
    CHECK(counters.IPv4 == 0);
    CHECK(counters.IPv6 == 360);
    CHECK(counters.queries == 180);
    CHECK(counters.replies == 180);
    CHECK(j["top_qname2"][0]["name"] == ".test.com");
    CHECK(j["top_qname2"][0]["estimate"] == 360);
}
