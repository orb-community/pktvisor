#include "PcapInputStream.h"
#include <arpa/inet.h>
#include <catch2/catch.hpp>

using namespace visor::input::pcap;
using namespace std::chrono;

TEST_CASE("Test mock traffic generator", "[pcap][mock]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.config_set("pcap_source", "mock");
    stream.parse_host_spec();

    stream.start();
    std::this_thread::sleep_for(1s);
    stream.stop();

}

