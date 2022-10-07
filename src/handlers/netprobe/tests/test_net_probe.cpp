#include <catch2/catch.hpp>

#include "NetProbeInputStream.h"
#include "NetProbeStreamHandler.h"

using namespace visor::handler::netprobe;
using namespace visor::input::netprobe;
using namespace nlohmann;

TEST_CASE("Parse Net Probe tests", "[pcap][netprobe]")
{
    NetProbeInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/netprobe.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler netprobe_handler{"netprobe-test", stream_proxy, &c};

    netprobe_handler.start();
    stream.start();
    netprobe_handler.stop();
    stream.stop();

    auto counters = netprobe_handler.metrics()->bucket(0)->counters();
    auto event_data = netprobe_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(netprobe_handler.metrics()->current_periods() == 1);
    CHECK(netprobe_handler.metrics()->start_tstamp().tv_sec == 1453594491);
    CHECK(netprobe_handler.metrics()->start_tstamp().tv_nsec == 508326000);

    CHECK(netprobe_handler.metrics()->end_tstamp().tv_sec == 1453594495);
    CHECK(netprobe_handler.metrics()->end_tstamp().tv_nsec == 971400000);

    CHECK(netprobe_handler.metrics()->bucket(0)->period_length() == 4);

    json j;
    netprobe_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 9);

    CHECK(counters.OPEN.value() == 2);
    CHECK(counters.UPDATE.value() == 4);
    CHECK(counters.filtered.value() == 0);
    CHECK(counters.total.value() == 9);

}
