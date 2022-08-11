#include <catch2/catch.hpp>

#include "DnsXactStreamHandler.h"
#include "dns.h"
#include "PcapInputStream.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wc99-extensions"
#pragma clang diagnostic ignored "-Wrange-loop-analysis"
#include <Packet.h>
#include <PcapFileDevice.h>
#include <ProtocolType.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <arpa/inet.h>
#pragma GCC diagnostic pop
#pragma GCC diagnostic ignored "-Wold-style-cast"

using namespace visor::handler::dnsxact;
using namespace visor::input::pcap;
using namespace nlohmann;

TEST_CASE("Parse DNS Xact UDP IPv4 tests", "[pcap][ipv4][udp][dns_xact]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv4_udp.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "127.0.0.0/24");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_xact_handler{"dns-test", stream_proxy, &c};

    dns_xact_handler.start();
    stream.start();
    dns_xact_handler.stop();
    stream.stop();

    auto counters = dns_xact_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_xact_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(dns_xact_handler.metrics()->current_periods() == 1);
    CHECK(dns_xact_handler.metrics()->start_tstamp().tv_sec == 1567706414);
    CHECK(dns_xact_handler.metrics()->start_tstamp().tv_nsec == 599964000);

    CHECK(dns_xact_handler.metrics()->end_tstamp().tv_sec == 1567706420);
    CHECK(dns_xact_handler.metrics()->end_tstamp().tv_nsec == 602866000);

    CHECK(dns_xact_handler.metrics()->bucket(0)->period_length() == 6);
    

    CHECK(dns_xact_handler.metrics()->current_periods() == 1);
    CHECK(event_data.num_events->value() == 140);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 0);
    CHECK(counters.xacts_total.value() == 70);
    CHECK(counters.xacts_timed_out.value() == 0);
}

TEST_CASE("Parse DNS Xact TCP IPv4 tests", "[pcap][ipv4][tcp][dns_xact]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv4_tcp.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_xact_handler{"dns-test", stream_proxy, &c};

    dns_xact_handler.start();
    stream.start();
    dns_xact_handler.stop();
    stream.stop();

    auto counters = dns_xact_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_xact_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 420);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 210);
    CHECK(counters.xacts_total.value() == 210);
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.filtered.value() == 0);
}

TEST_CASE("Parse DNS Xact UDP IPv6 tests", "[pcap][ipv6][udp][dns_xact]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv6_udp.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_xact_handler{"dns-test", stream_proxy, &c};

    dns_xact_handler.start();
    stream.start();
    stream.stop();
    dns_xact_handler.stop();

    auto counters = dns_xact_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_xact_handler.metrics()->bucket(0)->event_data_locked();
    json j;
    dns_xact_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 140);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 0);
    CHECK(counters.xacts_total.value() == 70);
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.filtered.value() == 0);
}

TEST_CASE("Parse DNS Xact TCP IPv6 tests", "[pcap][ipv6][tcp][dns_xact]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv6_tcp.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_xact_handler{"dns-test", stream_proxy, &c};

    dns_xact_handler.start();
    stream.start();
    stream.stop();
    dns_xact_handler.stop();

    auto counters = dns_xact_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_xact_handler.metrics()->bucket(0)->event_data_locked();
    json j;
    dns_xact_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 360);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 180);
    CHECK(counters.xacts_total.value() == 180);
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.filtered.value() == 0);
}

TEST_CASE("Parse DNS Xact random UDP/TCP tests", "[pcap][dns_xact]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_xact_handler{"dns-test", stream_proxy, &c};

    dns_xact_handler.start();
    stream.start();
    stream.stop();
    dns_xact_handler.stop();

    auto counters = dns_xact_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_xact_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark. there are 14 TCP retransmissions which are counted differently in our state machine
    // and account for some minor differences in TCP based stats
    CHECK(event_data.num_events->value() == 5851); // wireshark: 5838
    CHECK(event_data.num_samples->value() == 5851);
    CHECK(counters.xacts_total.value() == 2921); // wireshark: 2894
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 2921); // wireshark: 2894
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.filtered.value() == 0);
}

TEST_CASE("DNS Xact Filters: exclude_noerror", "[pcap][dns_xact]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_xact_handler{"dns-test", stream_proxy, &c};

    dns_xact_handler.config_set<bool>("exclude_noerror", true);

    dns_xact_handler.start();
    stream.start();
    stream.stop();
    dns_xact_handler.stop();

    auto counters = dns_xact_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_xact_handler.metrics()->bucket(0)->event_data_locked();

    REQUIRE(event_data.num_events->value() == 24);
    REQUIRE(event_data.num_samples->value() == 24);
    REQUIRE(counters.xacts_total.value() == 2);
    REQUIRE(counters.xacts_in.value() == 0);
    REQUIRE(counters.xacts_out.value() == 2);
    REQUIRE(counters.xacts_timed_out.value() == 0);
    REQUIRE(counters.filtered.value() == 10);
    nlohmann::json j;
    dns_xact_handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["xact"]["packets"]["filtered"] == 10);
}

TEST_CASE("DNS Xact Filters: only_rcode nx", "[pcap][net]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_xact_handler{"dns-test", stream_proxy, &c};

    dns_xact_handler.config_set<uint64_t>("only_rcode", NXDomain);

    dns_xact_handler.start();
    stream.start();
    stream.stop();
    dns_xact_handler.stop();

    auto counters = dns_xact_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_xact_handler.metrics()->bucket(0)->event_data_locked();

    REQUIRE(event_data.num_events->value() == 24);
    REQUIRE(event_data.num_samples->value() == 24);
    REQUIRE(counters.xacts_total.value() == 1);
    REQUIRE(counters.xacts_in.value() == 0);
    REQUIRE(counters.xacts_out.value() == 1);
    REQUIRE(counters.xacts_timed_out.value() == 0);
    REQUIRE(counters.filtered.value() == 11);
    nlohmann::json j;
    dns_xact_handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["xact"]["packets"]["filtered"] == 11);
}

TEST_CASE("DNS Xact Filters: only_rcode refused", "[pcap][dns_xact]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_xact_handler{"dns-test", stream_proxy, &c};

    dns_xact_handler.config_set<uint64_t>("only_rcode", Refused);

    dns_xact_handler.start();
    stream.start();
    stream.stop();
    dns_xact_handler.stop();

    auto counters = dns_xact_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_xact_handler.metrics()->bucket(0)->event_data_locked();

    REQUIRE(event_data.num_events->value() == 24);
    REQUIRE(event_data.num_samples->value() == 24);
    REQUIRE(counters.xacts_total.value() == 1);
    REQUIRE(counters.xacts_in.value() == 0);
    REQUIRE(counters.xacts_out.value() == 1);
    REQUIRE(counters.xacts_timed_out.value() == 0);
    REQUIRE(counters.filtered.value() == 11);
    nlohmann::json j;
    dns_xact_handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["xact"]["packets"]["filtered"] == 11);
}

TEST_CASE("DNS Xact Filters: only_qname_suffix", "[pcap][dns_xact]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_xact_handler{"dns-test", stream_proxy, &c};

    // notice, case insensitive
    dns_xact_handler.config_set<visor::Configurable::StringList>("only_qname_suffix", {"GooGle.com"});
    dns_xact_handler.start();
    stream.start();
    stream.stop();
    dns_xact_handler.stop();

    auto counters = dns_xact_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_xact_handler.metrics()->bucket(0)->event_data_locked();

    REQUIRE(event_data.num_events->value() == 24);
    REQUIRE(event_data.num_samples->value() == 24);
    REQUIRE(counters.xacts_total.value() == 5);
    REQUIRE(counters.xacts_in.value() == 0);
    REQUIRE(counters.xacts_out.value() == 5);
    REQUIRE(counters.xacts_timed_out.value() == 0);
    CHECK(counters.filtered.value() == 14);
}

TEST_CASE("DNS Xact Filters: answer_count", "[pcap][dns_xact]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_xact_handler{"dns-test", stream_proxy, &c};
    dns_xact_handler.config_set<uint64_t>("only_rcode", NoError);
    dns_xact_handler.config_set<uint64_t>("answer_count", 0);
    dns_xact_handler.start();
    stream.start();
    stream.stop();
    dns_xact_handler.stop();

    auto counters = dns_xact_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_xact_handler.metrics()->bucket(0)->event_data_locked();

    REQUIRE(event_data.num_events->value() == 24);
    REQUIRE(event_data.num_samples->value() == 24);
    REQUIRE(counters.xacts_total.value() == 4);
    REQUIRE(counters.xacts_in.value() == 0);
    REQUIRE(counters.xacts_out.value() == 4);
    REQUIRE(counters.xacts_timed_out.value() == 0);
    CHECK(counters.filtered.value() == 8);
}

TEST_CASE("DNS Xact Configs: public_suffix_list", "[pcap][dns_xact]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_xact_handler{"dns-test", stream_proxy, &c};

    // notice, case insensitive
    dns_xact_handler.config_set<bool>("public_suffix_list", true);
    dns_xact_handler.start();
    stream.start();
    stream.stop();
    dns_xact_handler.stop();

    auto counters = dns_xact_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_xact_handler.metrics()->bucket(0)->event_data_locked();

    REQUIRE(event_data.num_events->value() == 24);
    REQUIRE(event_data.num_samples->value() == 24);
    REQUIRE(counters.xacts_total.value() == 12);
    REQUIRE(counters.xacts_in.value() == 0);
    REQUIRE(counters.xacts_out.value() == 12);
    REQUIRE(counters.xacts_timed_out.value() == 0);
    REQUIRE(counters.filtered.value() == 0);
}

TEST_CASE("DNS Xact filter exceptions", "[pcap][dns_xact][filter]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_xact_handler{"dns-test", stream_proxy, &c};

    SECTION("only_rcode as string")
    {
        dns_xact_handler.config_set<std::string>("only_rcode", "1");
        REQUIRE_THROWS_WITH(dns_xact_handler.start(), "DnsXactStreamHandler: wrong value type for only_rcode filter. It should be an integer");
    }

    SECTION("only_rcode invalid")
    {
        dns_xact_handler.config_set<uint64_t>("only_rcode", 133);
        REQUIRE_THROWS_WITH(dns_xact_handler.start(), "DnsXactStreamHandler: only_rcode filter contained an invalid/unsupported rcode");
    }

    SECTION("answer_count as string")
    {
        dns_xact_handler.config_set<std::string>("answer_count", "1");
        REQUIRE_THROWS_WITH(dns_xact_handler.start(), "DnsXactStreamHandler: wrong value type for answer_count filter. It should be an integer");
    }
}
