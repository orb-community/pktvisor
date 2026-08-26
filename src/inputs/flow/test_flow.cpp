#include "FlowInputStream.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/catch_test_visor.hpp>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <uvw/loop.h>
#include <uvw/udp.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

using namespace visor::input::flow;

TEST_CASE("sflow pcap file", "[flow][sflow][file]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    CHECK_NOTHROW(stream.start());
    CHECK_NOTHROW(stream.stop());

    CHECK(stream.schema_key() == "flow");
    CHECK(stream.consumer_count() == 0);

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["flow"]["packet_errors"] == 0);
    CHECK(j["module"]["config"]["pcap_file"] == "tests/fixtures/ecmp.pcap");
}

TEST_CASE("netflow pcap file", "[flow][netflow][file]")
{

    FlowInputStream stream{"netflow-test"};
    stream.config_set("pcap_file", "tests/fixtures/nf9.pcap");
    stream.config_set("flow_type", "netflow");

    CHECK_NOTHROW(stream.start());
    CHECK_NOTHROW(stream.stop());

    CHECK(stream.schema_key() == "flow");
    CHECK(stream.consumer_count() == 0);

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["flow"]["packet_errors"] == 0);
    CHECK(j["module"]["config"]["pcap_file"] == "tests/fixtures/nf9.pcap");
}

TEST_CASE("sflow udp socket", "[sflow][udp]")
{

    std::string bind = "127.0.0.1";
    uint64_t port = 6343;

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("bind", bind);
    stream.config_set("port", port);

    CHECK_NOTHROW(stream.start());

    auto loop = uvw::loop::get_default();
    auto client = loop->resource<uvw::udp_handle>();
    client->on<uvw::send_event>([](const uvw::send_event &, uvw::udp_handle &handle) {
        handle.close();
    });
    auto dataSend = std::unique_ptr<char[]>(new char[2]{'b', 'c'});
    client->send(uvw::socket_address{bind, static_cast<unsigned int>(port)}, dataSend.get(), 2);
    client->send(bind, port, nullptr, 0);

    uv_sleep(100);

    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["flow"]["packet_errors"] == 1);
}

TEST_CASE("netflow udp socket", "[netflow][udp]")
{

    std::string bind = "127.0.0.1";
    uint64_t port = 6344;

    FlowInputStream stream{"netflow-test"};
    stream.config_set("flow_type", "netflow");
    stream.config_set("bind", bind);
    stream.config_set("port", port);

    CHECK_NOTHROW(stream.start());

    auto loop = uvw::loop::get_default();
    auto client = loop->resource<uvw::udp_handle>();
    client->on<uvw::send_event>([](const uvw::send_event &, uvw::udp_handle &handle) {
        handle.close();
    });
    auto dataSend = std::unique_ptr<char[]>(new char[2]{'b', 'c'});
    client->send(uvw::socket_address{bind, static_cast<unsigned int>(port)}, dataSend.get(), 2);
    client->send(bind, port, nullptr, 0);

    uv_sleep(100);

    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["flow"]["packet_errors"] == 1);
}

TEST_CASE("sflow udp socket without bind", "[flow][sflow][udp]")
{
    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");

    CHECK_THROWS_WITH(stream.start(), "flow config must specify port and bind");
}

TEST_CASE("netflow v9 with options flowset does not cause packet errors", "[flow][netflow][options-flowset]")
{
    // Fixture carries two datagrams: one with a real data flowset alongside
    // an options flowset (options template id 256) that pktvisor now
    // parses and recognizes, and one that is a pure template refresh with
    // zero data flowsets. Neither should be counted as a parse error.
    FlowInputStream stream{"netflow-options-test"};
    stream.config_set("pcap_file", "tests/fixtures/nf9_options.pcap");
    stream.config_set("flow_type", "netflow");

    CHECK_NOTHROW(stream.start());
    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["flow"]["packet_errors"] == 0);
}

TEST_CASE("ipfix with options set does not cause packet errors", "[flow][netflow][options-flowset]")
{
    FlowInputStream stream{"ipfix-options-test"};
    stream.config_set("pcap_file", "tests/fixtures/ipfix_options.pcap");
    stream.config_set("flow_type", "netflow");

    CHECK_NOTHROW(stream.start());
    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["flow"]["packet_errors"] == 0);
}
