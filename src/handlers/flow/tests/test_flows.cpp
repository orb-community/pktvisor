#include <catch2/catch.hpp>

#include "FlowInputStream.h"
#include "FlowStreamHandler.h"
#include "GeoDB.h"

using namespace visor::handler::flow;

TEST_CASE("Parse sflow stream", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", &stream, &c};

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto counters = flow_handler.metrics()->bucket(0)->counters();
    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);
    CHECK(counters.TCP.value() == 52785);
    CHECK(counters.UDP.value() == 0);
    CHECK(counters.IPv4.value() == 52785);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.OtherL4.value() == 0);
    CHECK(counters.filtered.value() == 0);
    CHECK(counters.total.value() == 52785);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cardinality"]["dst_ips_out"] == 4);
    CHECK(j["cardinality"]["src_ips_in"] == 4);
    CHECK(j["cardinality"]["dst_ports_out"] == 31);
    CHECK(j["cardinality"]["src_ports_in"] == 31);
    CHECK(j["top_src_ips_bytes"][0]["estimate"] == 39241798);
    CHECK(j["top_src_ips_bytes"][0]["name"] == "10.4.1.2");
    CHECK(j["top_src_ips_packets"][0]["estimate"] == 25853);
    CHECK(j["top_src_ips_packets"][0]["name"] == "10.4.1.2");
    CHECK(j["payload_size"]["p50"] == 1518);
}

TEST_CASE("Parse sflow stream with host filter", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", &stream, &c};
    flow_handler.config_set<visor::Configurable::StringList>("only_hosts", {"10.4.3.2/24"});

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto counters = flow_handler.metrics()->bucket(0)->counters();
    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);
    CHECK(counters.TCP.value() == 25731);
    CHECK(counters.UDP.value() == 0);
    CHECK(counters.IPv4.value() == 25731);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.OtherL4.value() == 0);
    CHECK(counters.filtered.value() == 27054);
    CHECK(counters.total.value() == 25731);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cardinality"]["dst_ips_out"] == 2);
    CHECK(j["cardinality"]["src_ips_in"] == 2);
    CHECK(j["cardinality"]["dst_ports_out"] == 16);
    CHECK(j["cardinality"]["src_ports_in"] == 16);
    CHECK(j["top_src_ips_bytes"][0]["estimate"] == 37409542);
    CHECK(j["top_src_ips_bytes"][0]["name"] == "10.4.3.2");
    CHECK(j["top_src_ips_packets"][0]["estimate"] == 24649);
    CHECK(j["top_src_ips_packets"][0]["name"] == "10.4.3.2");
    CHECK(j["payload_size"]["p50"] == 1518);
}

TEST_CASE("Parse netflow stream", "[netflow][flow]")
{

    FlowInputStream stream{"netflow-test"};
    stream.config_set("flow_type", "netflow");
    stream.config_set("pcap_file", "tests/fixtures/nf9.pcap");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", &stream, &c};

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto counters = flow_handler.metrics()->bucket(0)->counters();
    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 1);
    CHECK(event_data.num_samples->value() == 1);
    CHECK(counters.TCP.value() == 0);
    CHECK(counters.UDP.value() == 0);
    CHECK(counters.IPv4.value() == 24);
    CHECK(counters.IPv6.value() == 0);
    CHECK(counters.OtherL4.value() == 24);
    CHECK(counters.total.value() == 24);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cardinality"]["dst_ips_out"] == 24);
    CHECK(j["cardinality"]["src_ips_in"] == 24);
    CHECK(j["cardinality"]["dst_ports_out"] == 0);
    CHECK(j["cardinality"]["src_ports_in"] == 0);
    CHECK(j["top_src_ips_bytes"][0]["estimate"] == 6066232);
    CHECK(j["top_src_ips_packets"][0]["estimate"] == 7858);
    CHECK(j["payload_size"]["p50"] == 5926641);
}