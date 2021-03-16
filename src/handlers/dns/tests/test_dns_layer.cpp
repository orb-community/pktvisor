#include <catch2/catch.hpp>

#include "DnsStreamHandler.h"
#include "PcapInputStream.h"

using namespace visor::handler::dns;
using namespace visor::input::pcap;
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
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(dns_handler.metrics()->current_periods() == 1);
    CHECK(dns_handler.metrics()->start_tstamp().tv_sec == 1567706414);
    CHECK(dns_handler.metrics()->start_tstamp().tv_nsec == 599964000);

    CHECK(dns_handler.metrics()->end_tstamp().tv_sec == 1567706420);
    CHECK(dns_handler.metrics()->end_tstamp().tv_nsec == 602866000);

    CHECK(dns_handler.metrics()->bucket(0)->period_length() == 6);

    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(dns_handler.metrics()->current_periods() == 1);
    CHECK(event_data.num_events->value() == 140);
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
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 420);
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
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 140);
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
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 360);
    CHECK(counters.TCP == 360);
    CHECK(counters.IPv4 == 0);
    CHECK(counters.IPv6 == 360);
    CHECK(counters.queries == 180);
    CHECK(counters.replies == 180);
    CHECK(j["top_qname2"][0]["name"] == ".test.com");
    CHECK(j["top_qname2"][0]["estimate"] == 360);
}

TEST_CASE("Parse DNS random UDP/TCP tests", "[pcap][net]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    DnsStreamHandler dns_handler{"dns-test", &stream, 1, 100};

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark. there are 14 TCP retransmissions which are counted differently in our state machine
    // and account for some minor differences in TCP based stats
    CHECK(event_data.num_events->value() == 5851); // wireshark: 5838
    CHECK(event_data.num_samples->value() == 5851);
    CHECK(counters.TCP == 2880); // wireshark: 2867
    CHECK(counters.UDP == 2971);
    CHECK(counters.IPv4 == 5851); // wireshark: 5838
    CHECK(counters.IPv6 == 0);
    CHECK(counters.queries == 2930);
    CHECK(counters.replies == 2921);     // wireshark: 2908
    CHECK(counters.xacts_total == 2921); // wireshark: 2894
    CHECK(counters.xacts_in == 0);
    CHECK(counters.xacts_out == 2921); // wireshark: 2894
    CHECK(counters.xacts_timed_out == 0);
    CHECK(counters.NOERROR == 2921); // wireshark: 5838 (we only count reply result codes)
    CHECK(counters.NOERROR == 2921); // wireshark: 5838 (we only count reply result codes)
    CHECK(counters.NX == 0);
    CHECK(counters.REFUSED == 0);
    CHECK(counters.SRVFAIL == 0);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cardinality"]["qname"] == 2055); // flame was run with 1000 randoms x2 (udp+tcp)

    CHECK(j["top_qname2"][0]["name"] == ".test.com");
    CHECK(j["top_qname2"][0]["estimate"] == event_data.num_events->value());

    CHECK(j["top_rcode"][0]["name"] == "NOERROR");
    CHECK(j["top_rcode"][0]["estimate"] == counters.NOERROR);

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
