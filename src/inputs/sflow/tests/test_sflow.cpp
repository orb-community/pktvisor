#include "SflowInputStream.h"
#include <catch2/catch.hpp>

using namespace visor::input::sflow;

TEST_CASE("sflow pcap file", "[sflow][file]")
{

    SflowInputStream stream{"sflow-test"};
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    CHECK_NOTHROW(stream.start());
    CHECK_NOTHROW(stream.stop());
}

TEST_CASE("sflow udp socket", "[sflow][udp]")
{

    SflowInputStream stream{"sflow-test"};
    stream.config_set("bind", "127.0.0.1");
    stream.config_set("port", static_cast<uint64_t>(6343));

    CHECK_NOTHROW(stream.start());
    CHECK_NOTHROW(stream.stop());
}

TEST_CASE("sflow udp socket without bind", "[sflow][udp]")
{
    SflowInputStream stream{"sflow-test"};

    CHECK_THROWS_WITH(stream.start(), "sflow config must specify port and bind");
}
