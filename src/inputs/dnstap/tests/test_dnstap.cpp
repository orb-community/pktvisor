
#include <catch2/catch.hpp>
#include "DnstapInputStream.h"

using namespace visor::input::dnstap;

TEST_CASE("dnstap file", "[dnstap][file]")
{

    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");

    stream.start();
    stream.stop();
}

TEST_CASE("dnstap socket", "[dnstap][socket]")
{

    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("socket", "/tmp/dnstap-test.sock");

    stream.start();
    stream.stop();
}
