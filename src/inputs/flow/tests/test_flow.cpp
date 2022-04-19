#include "FlowInputStream.h"
#include <catch2/catch.hpp>

using namespace visor::input::flow;

TEST_CASE("sflow pcap file", "[flow][sflow][file]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    CHECK_NOTHROW(stream.start());
    CHECK_NOTHROW(stream.stop());

    CHECK(stream.schema_key() == "sflow");
    CHECK(stream.consumer_count() == 0);

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["sflow"]["packet_errors"] == 0);
    CHECK(j["module"]["config"]["pcap_file"] == "tests/fixtures/ecmp.pcap");
}

TEST_CASE("sflow udp socket", "[sflow][udp]")
{

    std::string bind = "127.0.0.1";
    uint64_t port = 6343;

    FlowInputStream stream{"sflow-test"};
    stream.config_set("bind", bind);
    stream.config_set("port", port);

    CHECK_NOTHROW(stream.start());

    auto loop = uvw::Loop::getDefault();
    auto client = loop->resource<uvw::UDPHandle>();
    client->once<uvw::SendEvent>([](const uvw::SendEvent &, uvw::UDPHandle &handle) {
        handle.close();
    });
    auto dataSend = std::unique_ptr<char[]>(new char[2]{'b', 'c'});
    client->send(uvw::Addr{bind, static_cast<unsigned int>(port)}, dataSend.get(), 2);
    client->send(bind, port, nullptr, 0);

    uv_sleep(100);

    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["sflow"]["packet_errors"] == 1);
}

TEST_CASE("sflow udp socket without bind", "[flow][sflow][udp]")
{
    FlowInputStream stream{"sflow-test"};

    CHECK_THROWS_WITH(stream.start(), "sflow config must specify port and bind");
}
