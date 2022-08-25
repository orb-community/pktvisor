#include <catch2/catch.hpp>

#include "DnsXactStreamHandler.h"
#include "GeoDB.h"
#include "PcapInputStream.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wc99-extensions"
#pragma clang diagnostic ignored "-Wrange-loop-analysis"
#include <DnsLayer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <ProtocolType.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <arpa/inet.h>
#pragma GCC diagnostic pop
#pragma GCC diagnostic ignored "-Wold-style-cast"

using namespace visor::handler::dns;
using namespace visor::input::pcap;
using namespace nlohmann;

TEST_CASE("Ensure we use only pktvisor DnsLayer", "[pcap][ipv4][dns]")
{

    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("tests/fixtures/dns_udp_tcp_random.pcap");

    CHECK(reader->open());

    pcpp::RawPacket rawPacket;

    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet dnsRequest(&rawPacket, pcpp::TCP | pcpp::UDP);
        if (dnsRequest.isPacketOfType(pcpp::UDP)) {
            CHECK(dnsRequest.getLayerOfType<pcpp::UdpLayer>() != nullptr);
        } else {
            CHECK(dnsRequest.getLayerOfType<pcpp::TcpLayer>() != nullptr);
        }
        // we do NOT expect to see pcpp::DnsLayer or DNS protocol yet
        CHECK(dnsRequest.getLayerOfType<pcpp::DnsLayer>() == nullptr);
        CHECK(dnsRequest.getLayerOfType<pcpp::DnsOverTcpLayer>() == nullptr);
        CHECK(dnsRequest.isPacketOfType(pcpp::DNS) == false);
    }

    reader->close();
    delete reader;
}

TEST_CASE("Parse DNS UDP IPv6 tests", "[pcap][ipv6][udp][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv6_udp.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 140);
    CHECK(counters.xacts_total.value() == 70);
    CHECK(counters.xacts_unknown_dir.value() == 70);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 0);
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.xacts_filtered.value() == 0);
}

TEST_CASE("Parse DNS TCP IPv6 tests", "[pcap][ipv6][tcp][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv6_tcp.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();
    json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 360);
    CHECK(counters.xacts_total.value() == 180);
    CHECK(counters.xacts_unknown_dir.value() == 0);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 180);
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.xacts_filtered.value() == 0);
}

TEST_CASE("Parse DNS random UDP/TCP tests", "[pcap][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_handler{"dns-test", stream_proxy, &c};

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
    CHECK(counters.xacts_unknown_dir.value() == 0);
    CHECK(counters.xacts_total.value() == 2921); // wireshark: 2894
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 2921); // wireshark: 2894
    CHECK(counters.xacts_timed_out.value() == 0);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["xact"]["counts"]["total"] == 2921);
}

TEST_CASE("DNS Filters: only_qtypes AAAA and TXT", "[pcap][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    //notice case insensitive
    dns_handler.config_set<visor::Configurable::StringList>("only_qtype", {"AAAA", "TxT"});
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
    CHECK(counters.xacts_total.value() == 1046);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 1046);
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.xacts_filtered.value() == 1875);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);
    CHECK(j["xact"]["counts"]["total"] == 1046);
}

TEST_CASE("DNS Filters: only_qname_suffix", "[pcap][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    // notice, case insensitive
    dns_handler.config_set<visor::Configurable::StringList>("only_qname_suffix", {"GooGle.com"});
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();

    CHECK(counters.xacts_total.value() == 5);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 5);
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.xacts_filtered.value() == 14);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["xact"]["counts"]["total"] == 5);
}

TEST_CASE("DNS Filters: only_dnssec_response", "[pcap][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dnssec.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_handler{"dns-test", stream_proxy, &c};
    dns_handler.config_set<bool>("only_dnssec_response", true);
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 14);
    CHECK(event_data.num_samples->value() == 14);
    CHECK(counters.xacts_total.value() == 6);
    CHECK(counters.xacts_unknown_dir.value() == 6);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 0);
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.xacts_filtered.value() == 1);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["xact"]["counts"]["total"] == 6);
}

TEST_CASE("DNS filter: GeoLoc not found", "[pcap][dns][ecs]")
{
    CHECK_NOTHROW(visor::geo::GeoIP().enable("tests/fixtures/GeoIP2-City-Test.mmdb"));
    CHECK_NOTHROW(visor::geo::GeoASN().enable("tests/fixtures/GeoIP2-ISP-Test.mmdb"));

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/ecs.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_handler{"dns-test", stream_proxy, &c};
    dns_handler.config_set<visor::Configurable::StringList>("enable", visor::Configurable::StringList({"top_ecs"}));
    dns_handler.config_set<bool>("geoloc_notfound", true);
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 36);
    CHECK(event_data.num_samples->value() == 36);
    CHECK(counters.xacts_total.value() == 2);
    CHECK(counters.xacts_unknown_dir.value() == 2);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 0);
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.xacts_filtered.value() == 17);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["xact"]["counts"]["total"] == 2);
}

TEST_CASE("DNS filter: ASN not found", "[pcap][dns][ecs]")
{
    CHECK_NOTHROW(visor::geo::GeoIP().enable("tests/fixtures/GeoIP2-City-Test.mmdb"));
    CHECK_NOTHROW(visor::geo::GeoASN().enable("tests/fixtures/GeoIP2-ISP-Test.mmdb"));

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/ecs.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_handler{"dns-test", stream_proxy, &c};
    dns_handler.config_set<visor::Configurable::StringList>("enable", visor::Configurable::StringList({"top_ecs"}));
    dns_handler.config_set<bool>("asn_notfound", true);
    dns_handler.start();
    stream.start();
    stream.stop();
    dns_handler.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();
    auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data.num_events->value() == 36);
    CHECK(event_data.num_samples->value() == 36);
    CHECK(counters.xacts_unknown_dir.value() == 2);
    CHECK(counters.xacts_total.value() == 2);
    CHECK(counters.xacts_in.value() == 0);
    CHECK(counters.xacts_out.value() == 0);
    CHECK(counters.xacts_timed_out.value() == 0);
    CHECK(counters.xacts_filtered.value() == 17);

    nlohmann::json j;
    dns_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["xact"]["counts"]["total"] == 2);
}

TEST_CASE("DNS filter exceptions", "[pcap][dns][filter]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    SECTION("only_rcode as string")
    {
        dns_handler.config_set<std::string>("only_rcode", "1");
        REQUIRE_THROWS_WITH(dns_handler.start(), "DnsXactStreamHandler: wrong value type for only_rcode filter. It should be an integer");
    }

    SECTION("only_rcode invalid")
    {
        dns_handler.config_set<uint64_t>("only_rcode", 133);
        REQUIRE_THROWS_WITH(dns_handler.start(), "DnsXactStreamHandler: only_rcode filter contained an invalid/unsupported rcode");
    }

    SECTION("only_qtype invalid qtype string")
    {
        dns_handler.config_set<visor::Configurable::StringList>("only_qtype", {"AAAA", "TEXT"});
        REQUIRE_THROWS_WITH(dns_handler.start(), "DnsXactStreamHandler: only_qtype filter contained an invalid/unsupported qtype: TEXT");
    }

    SECTION("only_qtype invalid qtype number")
    {
        dns_handler.config_set<visor::Configurable::StringList>("only_qtype", {"AAAA", "270"});
        REQUIRE_THROWS_WITH(dns_handler.start(), "DnsXactStreamHandler: only_qtype filter contained an invalid/unsupported qtype: 270");
    }

    SECTION("answer_count as string")
    {
        dns_handler.config_set<std::string>("answer_count", "1");
        REQUIRE_THROWS_WITH(dns_handler.start(), "DnsXactStreamHandler: wrong value type for answer_count filter. It should be an integer");
    }
}

TEST_CASE("DNS groups", "[pcap][dns]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_handler{"dns-test", stream_proxy, &c};

    SECTION("disable cardinality and counters")
    {
        dns_handler.config_set<visor::Configurable::StringList>("disable", {"cardinality", "counters"});

        dns_handler.start();
        stream.start();
        stream.stop();
        dns_handler.stop();

        auto counters = dns_handler.metrics()->bucket(0)->counters();
        auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

        CHECK(event_data.num_events->value() == 5851);
        CHECK(event_data.num_samples->value() == 5851);
        CHECK(counters.xacts_total.value() == 2921);
        CHECK(counters.xacts_in.value() == 0);
        CHECK(counters.xacts_out.value() == 2921);
        CHECK(counters.xacts_timed_out.value() == 0);

        nlohmann::json j;
        dns_handler.metrics()->bucket(0)->to_json(j);

        CHECK(j["xact"]["counts"]["total"] == 2921);
        CHECK(j["xact"]["ratio"]["quantiles"]["p50"] != nullptr);
    }

    SECTION("disable TopQname and Dns Transactions")
    {
        dns_handler.config_set<visor::Configurable::StringList>("disable", {"top_qnames", "dns_transaction"});

        dns_handler.start();
        stream.start();
        stream.stop();
        dns_handler.stop();

        auto counters = dns_handler.metrics()->bucket(0)->counters();
        auto event_data = dns_handler.metrics()->bucket(0)->event_data_locked();

        CHECK(event_data.num_events->value() == 0);
        CHECK(event_data.num_samples->value() == 0);
        CHECK(counters.xacts_total.value() == 0);
        CHECK(counters.xacts_in.value() == 0);
        CHECK(counters.xacts_out.value() == 0);
        CHECK(counters.xacts_timed_out.value() == 0);

        nlohmann::json j;
        dns_handler.metrics()->bucket(0)->to_json(j);

        CHECK(j["xact"]["counts"]["total"] == nullptr);
    }

    SECTION("disable invalid dns group")
    {
        dns_handler.config_set<visor::Configurable::StringList>("disable", {"top_qnames", "dns_top_wired"});
        REQUIRE_THROWS_WITH(dns_handler.start(), "dns_top_wired is an invalid/unsupported metric group. The valid groups are cardinality, counters, dns_transaction, top_ecs, top_qnames");
    }

    SECTION("enable invalid dns group")
    {
        dns_handler.config_set<visor::Configurable::StringList>("enable", {"top_qnames", "dns_top_wired"});
        REQUIRE_THROWS_WITH(dns_handler.start(), "dns_top_wired is an invalid/unsupported metric group. The valid groups are cardinality, counters, dns_transaction, top_ecs, top_qnames");
    }
}

TEST_CASE("DNS Filters: only_rcode with predicate", "[pcap][dns][filter]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_mixed_rcode.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    DnsXactStreamHandler dns_handler_1{"dns-test-1", stream_proxy, &c};
    DnsXactStreamHandler dns_handler_2{"dns-test-2", stream_proxy, &c};

    dns_handler_1.config_set<uint64_t>("only_rcode", 2);
    dns_handler_2.config_set<uint64_t>("only_rcode", 3);

    dns_handler_1.start();
    dns_handler_2.start();
    stream.start();
    stream.stop();
    dns_handler_1.stop();
    dns_handler_2.stop();

    auto event_data_1 = dns_handler_1.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data_1.num_events->value() == 0);
    CHECK(event_data_1.num_samples->value() == 0);

    auto event_data_2 = dns_handler_2.metrics()->bucket(0)->event_data_locked();

    CHECK(event_data_2.num_events->value() == 1);
    CHECK(event_data_2.num_samples->value() == 1);

    nlohmann::json j;
    dns_handler_2.metrics()->bucket(0)->to_json(j);
    CHECK(j["xact"]["counts"]["total"] == 0);
}
