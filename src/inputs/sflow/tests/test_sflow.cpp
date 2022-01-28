#include "SflowInputStream.h"
#include <catch2/catch.hpp>

using namespace visor::input::sflow;

TEST_CASE("sflow pcap file", "[sflow][file]")
{

    SflowInputStream stream{"sflow-test"};
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    CHECK_NOTHROW(stream.start());
    CHECK_NOTHROW(stream.stop());

    CHECK(stream.schema_key() == "sflow");
    CHECK(stream.consumer_count() == 0);

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["module"]["config"]["pcap_file"] == "tests/fixtures/ecmp.pcap");
}

TEST_CASE("sflow udp socket", "[sflow][udp]")
{

    std::string bind = "127.0.0.1";
    uint64_t port = 6343;

    SflowInputStream stream{"sflow-test"};
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

    CHECK_NOTHROW(stream.stop());
}

TEST_CASE("sflow udp socket without bind", "[sflow][udp]")
{
    SflowInputStream stream{"sflow-test"};

    CHECK_THROWS_WITH(stream.start(), "sflow config must specify port and bind");
}
