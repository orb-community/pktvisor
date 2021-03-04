#include <catch2/catch.hpp>

#include "GeoDB.h"
#include "NetStreamHandler.h"
#include "PcapInputStream.h"

using namespace vizer::handler::net;
using namespace vizer::input::pcap;

TEST_CASE("Parse net (dns) UDP IPv4 tests", "[pcap][ipv4][udp][net]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "fixtures/dns_ipv4_udp.pcap");
    stream.config_set("bpf", std::string());

    NetStreamHandler net_handler{"net-test", &stream, 1, 100};

    net_handler.start();
    stream.start();
    net_handler.stop();
    stream.stop();

    auto counters = net_handler.metrics()->bucket(0)->counters();
    auto event_data = net_handler.metrics()->bucket(0)->event_data();

    CHECK(net_handler.metrics()->current_periods() == 1);
    CHECK(event_data.num_events == 140);
    CHECK(counters.UDP == 140);
    CHECK(counters.IPv4 == 140);
    CHECK(counters.IPv6 == 0);
}

TEST_CASE("Parse net (dns) TCP IPv4 tests", "[pcap][ipv4][tcp][net]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "fixtures/dns_ipv4_tcp.pcap");
    stream.config_set("bpf", "");

    NetStreamHandler net_handler{"net-test", &stream, 1, 100};

    net_handler.start();
    stream.start();
    net_handler.stop();
    stream.stop();

    auto counters = net_handler.metrics()->bucket(0)->counters();
    auto event_data = net_handler.metrics()->bucket(0)->event_data();

    CHECK(event_data.num_events == 2100);
    CHECK(counters.TCP == 2100);
    CHECK(counters.IPv4 == 2100);
    CHECK(counters.IPv6 == 0);
}

TEST_CASE("Parse net (dns) UDP IPv6 tests", "[pcap][ipv6][udp][net]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "fixtures/dns_ipv6_udp.pcap");
    stream.config_set("bpf", "");

    NetStreamHandler net_handler{"net-test", &stream, 1, 100};

    net_handler.start();
    stream.start();
    stream.stop();
    net_handler.stop();

    auto counters = net_handler.metrics()->bucket(0)->counters();
    auto event_data = net_handler.metrics()->bucket(0)->event_data();

    CHECK(event_data.num_events == 140);
    CHECK(counters.UDP == 140);
    CHECK(counters.IPv4 == 0);
    CHECK(counters.IPv6 == 140);
}

TEST_CASE("Parse net (dns) TCP IPv6 tests", "[pcap][ipv6][tcp][net]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "fixtures/dns_ipv6_tcp.pcap");
    stream.config_set("bpf", "");

    NetStreamHandler net_handler{"net-test", &stream, 1, 100};

    net_handler.start();
    stream.start();
    stream.stop();
    net_handler.stop();

    auto counters = net_handler.metrics()->bucket(0)->counters();
    auto event_data = net_handler.metrics()->bucket(0)->event_data();

    CHECK(event_data.num_events == 1800);
    CHECK(counters.TCP == 1800);
    CHECK(counters.IPv4 == 0);
    CHECK(counters.IPv6 == 1800);
}

TEST_CASE("Parse net (dns) random UDP/TCP tests", "[pcap][net]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    NetStreamHandler net_handler{"net-test", &stream, 1, 100};

    net_handler.start();
    stream.start();
    stream.stop();
    net_handler.stop();

    auto counters = net_handler.metrics()->bucket(0)->counters();
    auto event_data = net_handler.metrics()->bucket(0)->event_data();

    // confirmed with wireshark
    CHECK(event_data.num_events == 16147);
    CHECK(event_data.num_samples == 16147);
    CHECK(counters.TCP == 13176);
    CHECK(counters.UDP == 2971);
    CHECK(counters.IPv4 == 16147);
    CHECK(counters.IPv6 == 0);
    CHECK(counters.OtherL4 == 0);
    CHECK(counters.total_in == 6648);
    CHECK(counters.total_out == 9499);

    nlohmann::json j;
    net_handler.metrics()->bucket(0)->to_json(j);
    CHECK(j["cardinality"]["dst_ips_out"] == 1);
    CHECK(j["cardinality"]["src_ips_in"] == 1);
    CHECK(j["top_ipv4"][0]["estimate"] == 16147);
    CHECK(j["top_ipv4"][0]["name"] == "8.8.8.8");
}
