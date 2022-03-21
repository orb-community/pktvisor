#include <catch2/catch.hpp>

#include "DnstapInputStream.h"
#include "PcapInputStream.h"
#include "InputResourcesStreamHandler.h"
#include "SflowInputStream.h"

using namespace visor::handler::resources;

TEST_CASE("Check resources for pcap input", "[pcap][resources]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_ipv4_udp.pcap");
    stream.config_set("bpf", std::string());

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    InputResourcesStreamHandler resources_handler{"net-test", &stream, &c};

    resources_handler.start();
    stream.start();
    resources_handler.stop();
    stream.stop();

    auto event_data = resources_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(resources_handler.metrics()->current_periods() == 1);
    CHECK(event_data.num_events->value() == 1);

    nlohmann::json j;
    resources_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cpu_percentage"]["p50"] == 0.0);
    CHECK(j["memory_bytes"]["p50"] != nullptr);

    std::stringstream output;
    std::string line;
    resources_handler.metrics()->bucket(0)->to_prometheus(output, {{"policy", "default"}});
    std::getline(output, line);
    CHECK(line == "# HELP base_total Total number of events");
    std::getline(output, line);
    CHECK(line == "# TYPE base_total gauge");
    std::getline(output, line);
    CHECK(line == R"(base_total{policy="default"} 1)");
}

TEST_CASE("Check resources for dnstap input", "[dnstap][resources]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");
    stream.config_set<visor::Configurable::StringList>("only_hosts", {"192.168.0.0/24", "2001:db8::/48"});
    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    InputResourcesStreamHandler resources_handler{"net-test", &stream, &c};

    resources_handler.start();
    stream.start();
    stream.stop();
    resources_handler.stop();

    auto event_data = resources_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(resources_handler.metrics()->current_periods() == 1);
    CHECK(event_data.num_events->value() == 1);

    nlohmann::json j;
    resources_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cpu_percentage"]["p50"] == 0.0);
    CHECK(j["memory_bytes"]["p50"] != nullptr);
}

TEST_CASE("Check resources for sflow input", "[sflow][resources]")
{
    SflowInputStream stream{"sflow-test"};
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    InputResourcesStreamHandler resources_handler{"net-test", &stream, &c};

    resources_handler.start();
    stream.start();
    stream.stop();
    resources_handler.stop();

    auto event_data = resources_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(resources_handler.metrics()->current_periods() == 1);
    CHECK(event_data.num_events->value() == 1);

    nlohmann::json j;
    resources_handler.metrics()->bucket(0)->to_json(j);

    CHECK(j["cpu_percentage"]["p50"] == 0.0);
    CHECK(j["memory_bytes"]["p50"] != nullptr);
}