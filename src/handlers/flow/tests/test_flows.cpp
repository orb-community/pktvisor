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

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["dst_ips_out"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["src_ips_in"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["dst_ports_out"] == 23);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["src_ports_in"] == 9);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_bytes"][0]["estimate"] == 108027400000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_bytes"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ips_packets"][0]["estimate"] == 5160000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ips_packets"][0]["name"] == "10.4.4.2");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_dst_ports_bytes"][0]["estimate"] == 170879120000);
#if __APPLE__
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_dst_ports_bytes"][0]["name"] == "commplex-link");
#else
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_dst_ports_bytes"][0]["name"] == "5001");
#endif
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_and_port_bytes"][0]["estimate"] == 26838240000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_and_port_bytes"][0]["name"] == "10.4.1.2:57420");
}

TEST_CASE("Parse sflow with enrichment", "[sflow][flow]")
{
    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    auto stream_proxy = stream.add_event_proxy(c);
    c.config_set<uint64_t>("num_periods", 1);
    FlowStreamHandler flow_handler{"flow-test", stream_proxy, &c};
    flow_handler.config_set<visor::Configurable::StringList>("device_map", {"route1,192.168.0.11,eth0,37,provide Y", "route2,192.168.0.12,eth3,4"});
    flow_handler.config_set<visor::Configurable::StringList>("only_interfaces", {"37", "4", "52"});
    flow_handler.config_set<visor::Configurable::StringList>("enable", visor::Configurable::StringList({"top_interfaces"}));

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);
    CHECK(j["devices"]["route1"]["top_in_interfaces_bytes"][0]["name"] == "eth0");
    CHECK(j["devices"]["route2"]["top_in_interfaces_bytes"][0]["name"] == "eth3");
    CHECK(j["devices"]["192.168.0.13"]["top_in_interfaces_bytes"][0]["name"] == "52");
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

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["dst_ips_out"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["src_ips_in"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["dst_ports_out"] == 23);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["src_ports_in"] == 9);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_bytes"][0]["estimate"] == 5401370);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_bytes"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ips_packets"][0]["estimate"] == 258);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ips_packets"][0]["name"] == "10.4.4.2");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_dst_ports_bytes"][0]["estimate"] == 3010);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ips_and_port_bytes"][0]["estimate"] == 18060);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ips_and_port_bytes"][0]["name"] == "10.4.4.2:5001");
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

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["dst_ips_out"] == 2);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["src_ips_in"] == 2);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["dst_ports_out"] == 13);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["cardinality"]["src_ports_in"] == 4);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_bytes"][0]["estimate"] == 62851720000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_bytes"][0]["name"] == "10.4.3.2");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ips_packets"][0]["estimate"] == 5160000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_out_src_ips_packets"][0]["name"] == "10.4.4.2");
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_dst_ports_bytes"][0]["estimate"] == 62851720000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_and_port_bytes"][0]["estimate"] == 26443560000);
    CHECK(j["devices"]["192.168.0.13"]["interfaces"]["52"]["top_in_src_ips_and_port_bytes"][0]["name"] == "10.4.3.2:40268");
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
    flow_handler.config_set<visor::Configurable::StringList>("only_devices", {"192.168.0.11"});

    flow_handler.start();
    stream.start();
    stream.stop();
    flow_handler.stop();

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["dst_ips_out"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["src_ips_in"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["dst_ports_out"] == 16);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["src_ports_in"] == 16);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_in_src_ips_bytes"][0]["estimate"] == 264021720000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_in_src_ips_bytes"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_out_src_ips_packets"][0]["estimate"] == 8040000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_out_src_ips_packets"][0]["name"] == "10.4.2.2");
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_in_dst_ports_bytes"][0]["estimate"] == 264021720000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_out_src_ips_and_port_bytes"][0]["estimate"] == 563840000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_out_src_ips_and_port_bytes"][0]["name"] == "10.4.2.2:5001");

    CHECK(j["devices"]["192.168.0.13"]["records_filtered"] == 7189);
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

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.11"]["records_flows"] == 892);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"] == nullptr);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["cardinality"]["dst_ips_out"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["cardinality"]["src_ips_in"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["cardinality"]["dst_ports_out"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["cardinality"]["src_ports_in"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_out_src_ips_bytes"][0]["estimate"] == 71400000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_out_src_ips_bytes"][0]["name"] == "10.4.4.2");
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_in_src_ips_packets"][0]["estimate"] == 16820000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_in_src_ips_packets"][0]["name"] == "10.4.3.2");
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_in_dst_ports_bytes"][0]["estimate"] == 25532760000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_out_src_ips_and_port_bytes"][0]["estimate"] == 71400000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["38"]["top_out_src_ips_and_port_bytes"][0]["name"] == "10.4.4.2:5001");
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

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 9279);
    CHECK(event_data.num_samples->value() == 9279);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["dst_ips_out"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["src_ips_in"] == 2);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["dst_ports_out"] == 16);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["cardinality"]["src_ports_in"] == 16);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_in_src_ips_bytes"][0]["estimate"] == 264021720000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_in_src_ips_bytes"][0]["name"] == "10.4.1.2");
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_out_src_ips_packets"][0]["estimate"] == 8040000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_out_src_ips_packets"][0]["name"] == "10.4.2.2");
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_out_src_ips_and_port_bytes"][0]["estimate"] == 563840000);
    CHECK(j["devices"]["192.168.0.11"]["interfaces"]["37"]["top_out_src_ips_and_port_bytes"][0]["name"] == "10.4.2.2:5001");
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

    auto event_data = flow_handler.metrics()->bucket(0)->event_data_locked();

    // confirmed with wireshark
    CHECK(event_data.num_events->value() == 1);
    CHECK(event_data.num_samples->value() == 1);

    nlohmann::json j;
    flow_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["devices"]["192.168.100.1"]["records_flows"] == 24);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["0"]["cardinality"]["dst_ips_out"] == 24);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["0"]["cardinality"]["src_ips_in"] == 24);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["0"]["cardinality"]["dst_ports_out"] == 0);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["0"]["cardinality"]["src_ports_in"] == 0);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["0"]["top_in_src_ips_bytes"][0]["estimate"] == 6066232);
    CHECK(j["devices"]["192.168.100.1"]["interfaces"]["0"]["top_in_src_ips_packets"][0]["estimate"] == 7858);
}