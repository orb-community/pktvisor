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
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto counters = flow_handler.metrics()->bucket(0)->counters();
    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);
    CHECK(counters.filtered.value() == 0);
    CHECK(counters.total.value() == 52785);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.13"]["cardinality"]["dst_ips_out"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["cardinality"]["src_ips_in"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["cardinality"]["dst_ports_out"] == 23);
    CHECK(j["devices"]["192.168.0.13"]["cardinality"]["src_ports_in"] == 9);
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_bytes"][0]["estimate"] == 108027400000);
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_bytes"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_packets"][0]["estimate"] == 71180000);
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_packets"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.13"]["top_dst_ports_bytes"][0]["estimate"] == 170879120000);
    CHECK(j["devices"]["192.168.0.13"]["top_dst_ports_bytes"][0]["name"] == "5001");
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_and_port_bytes"][0]["estimate"] == 26838240000);
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_and_port_bytes"][0]["name"] == "10.4.1.2:57420");
    CHECK(j["devices"]["192.168.0.13"]["payload_size"]["p50"] == 30360000);
}

TEST_CASE("Parse sflow stream without sampling", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<bool>("sample_rate_scaling", false);

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto counters = flow_handler.metrics()->bucket(0)->counters();
    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);
    CHECK(counters.filtered.value() == 0);
    CHECK(counters.total.value() == 52785);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.13"]["cardinality"]["dst_ips_out"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["cardinality"]["src_ips_in"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["cardinality"]["dst_ports_out"] == 23);
    CHECK(j["devices"]["192.168.0.13"]["cardinality"]["src_ports_in"] == 9);
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_bytes"][0]["estimate"] == 5401370);
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_bytes"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_packets"][0]["estimate"] == 3559);
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_packets"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.13"]["top_dst_ports_bytes"][0]["estimate"] == 8543956);
    CHECK(j["devices"]["192.168.0.13"]["top_dst_ports_bytes"][0]["name"] == "5001");
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_and_port_bytes"][0]["estimate"] == 1341912);
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_and_port_bytes"][0]["name"] == "10.4.1.2:57420");
    CHECK(j["devices"]["192.168.0.13"]["payload_size"]["p50"] == 1518);
}

TEST_CASE("Parse sflow stream with ip filter", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<visor::Configurable::StringList>("only_ips", {"10.4.3.2/24"});

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto counters = flow_handler.metrics()->bucket(0)->counters();
    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);
    CHECK(counters.filtered.value() == 27054);
    CHECK(counters.total.value() == 25731);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.13"]["cardinality"]["dst_ips_out"] == 2);
    CHECK(j["devices"]["192.168.0.13"]["cardinality"]["src_ips_in"] == 2);
    CHECK(j["devices"]["192.168.0.13"]["cardinality"]["dst_ports_out"] == 13);
    CHECK(j["devices"]["192.168.0.13"]["cardinality"]["src_ports_in"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_bytes"][0]["estimate"] == 62851720000);
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_bytes"][0]["name"] == "10.4.3.2");
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_packets"][0]["estimate"] == 41420000);
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_packets"][0]["name"] == "10.4.3.2");
    CHECK(j["devices"]["192.168.0.13"]["top_dst_ports_bytes"][0]["estimate"] == 62851720000);
    CHECK(j["devices"]["192.168.0.13"]["top_dst_ports_bytes"][0]["name"] == "5001");
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_and_port_bytes"][0]["estimate"] == 26443560000);
    CHECK(j["devices"]["192.168.0.13"]["top_src_ips_and_port_bytes"][0]["name"] == "10.4.3.2:40268");
    CHECK(j["devices"]["192.168.0.13"]["payload_size"]["p50"] == 30360000);
}

TEST_CASE("Parse sflow stream with device filter", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<visor::Configurable::StringList>("only_devices", {"192.168.0.11/32"});

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto counters = flow_handler.metrics()->bucket(0)->counters();
    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);
    CHECK(counters.filtered.value() == 37968);
    CHECK(counters.total.value() == 17719);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.11"]["cardinality"]["dst_ips_out"] == 4);
    CHECK(j["devices"]["192.168.0.11"]["cardinality"]["src_ips_in"] == 4);
    CHECK(j["devices"]["192.168.0.11"]["cardinality"]["dst_ports_out"] == 31);
    CHECK(j["devices"]["192.168.0.11"]["cardinality"]["src_ports_in"] == 31);
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_bytes"][0]["estimate"] == 264021720000);
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_bytes"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_packets"][0]["estimate"] == 173940000);
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_packets"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.11"]["top_dst_ports_bytes"][0]["estimate"] == 513942960000);
    CHECK(j["devices"]["192.168.0.11"]["top_dst_ports_bytes"][0]["name"] == "5001");
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_and_port_bytes"][0]["estimate"] == 25532760000);
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_and_port_bytes"][0]["name"] == "10.4.3.2:40265");
    CHECK(j["devices"]["192.168.0.11"]["payload_size"]["p50"] == 30360000);

    CHECK(j["devices"]["192.168.0.13"] == nullptr);
}

TEST_CASE("Parse sflow stream with port filter", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<visor::Configurable::StringList>("only_ports", {"40265", "40400-40500"});

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto counters = flow_handler.metrics()->bucket(0)->counters();
    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);
    CHECK(counters.filtered.value() == 50235);
    CHECK(counters.total.value() == 2550);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.11"]["cardinality"]["dst_ips_out"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["cardinality"]["src_ips_in"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["cardinality"]["dst_ports_out"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["cardinality"]["src_ports_in"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_bytes"][0]["estimate"] == 25532760000);
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_bytes"][0]["name"] == "10.4.3.2");
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_packets"][0]["estimate"] == 16820000);
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_packets"][0]["name"] == "10.4.3.2");
    CHECK(j["devices"]["192.168.0.11"]["top_dst_ports_bytes"][0]["estimate"] == 25532760000);
    CHECK(j["devices"]["192.168.0.11"]["top_dst_ports_bytes"][0]["name"] == "5001");
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_and_port_bytes"][0]["estimate"] == 25532760000);
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_and_port_bytes"][0]["name"] == "10.4.3.2:40265");
    CHECK(j["devices"]["192.168.0.11"]["payload_size"]["p50"] == 30360000);
}

TEST_CASE("Parse sflow stream with interfaces filter", "[sflow][flow]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<visor::Configurable::StringList>("only_interfaces", {"4", "35-37"});

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto counters = flow_handler.metrics()->bucket(0)->counters();
    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);
    CHECK(counters.filtered.value() == 26128);
    CHECK(counters.total.value() == 26657);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.11"]["cardinality"]["dst_ips_out"] == 4);
    CHECK(j["devices"]["192.168.0.11"]["cardinality"]["src_ips_in"] == 4);
    CHECK(j["devices"]["192.168.0.11"]["cardinality"]["dst_ports_out"] == 28);
    CHECK(j["devices"]["192.168.0.11"]["cardinality"]["src_ports_in"] == 19);
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_bytes"][0]["estimate"] == 264021720000);
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_bytes"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_packets"][0]["estimate"] == 173940000);
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_packets"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.11"]["top_dst_ports_bytes"][0]["estimate"] == 325652520000);
    CHECK(j["devices"]["192.168.0.11"]["top_dst_ports_bytes"][0]["name"] == "5001");
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_and_port_bytes"][0]["estimate"] == 25431760000);
    CHECK(j["devices"]["192.168.0.11"]["top_src_ips_and_port_bytes"][0]["name"] == "10.4.1.2:57434");
    CHECK(j["devices"]["192.168.0.11"]["payload_size"]["p50"] == 30360000);
}

TEST_CASE("Parse netflow stream", "[netflow][flow]")
{

    FlowInputStream stream{"netflow-test"};
    stream.config_set("flow_type", "netflow");
    stream.config_set("pcap_file", "tests/fixtures/nf9.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto counters = flow_handler.metrics()->bucket(0)->counters();
    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 1);
    CHECK(event_data.num_samples->value() == 1);
    CHECK(counters.total.value() == 24);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.100.1"]["cardinality"]["dst_ips_out"] == 24);
    CHECK(j["devices"]["192.168.100.1"]["cardinality"]["src_ips_in"] == 24);
    CHECK(j["devices"]["192.168.100.1"]["cardinality"]["dst_ports_out"] == 0);
    CHECK(j["devices"]["192.168.100.1"]["cardinality"]["src_ports_in"] == 0);
    CHECK(j["devices"]["192.168.100.1"]["top_src_ips_bytes"][0]["estimate"] == 6066232);
    CHECK(j["devices"]["192.168.100.1"]["top_src_ips_packets"][0]["estimate"] == 7858);
    CHECK(j["devices"]["192.168.100.1"]["payload_size"]["p50"] == 5926641);
}