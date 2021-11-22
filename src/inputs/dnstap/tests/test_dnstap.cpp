
#include <catch2/catch.hpp>
#include "DnstapInputStream.h"

using namespace visor::input::dnstap;

TEST_CASE("dnstap", "[dnstap]")
{

    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/dnstap.pcap");

    stream.start();
    stream.stop();

}
