#include <catch2/catch.hpp>

#include "PcapInputStream.h"
#include "DhcpStreamHandler.h"

using namespace visor::handler::dhcp;
using namespace visor::input::pcap;
using namespace nlohmann;

TEST_CASE("Parse DHCP tests", "[pcap][dhcp]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dhcp-flow.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    DhcpStreamHandler dhcp_handler{"dhcp-test", stream_proxy, &c};

    dhcp_handler.start();
    stream.start();
    dhcp_handler.stop();
    stream.stop();

    auto counters = dhcp_handler.metrics()->bucket(0)->counters();
    auto event_data = dhcp_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(dhcp_handler.metrics()->current_periods() == 1);
    CHECK(dhcp_handler.metrics()->start_tstamp().tv_sec == 1634851620);
    CHECK(dhcp_handler.metrics()->start_tstamp().tv_nsec == 703423000);

    CHECK(dhcp_handler.metrics()->end_tstamp().tv_sec == 1634851650);
    CHECK(dhcp_handler.metrics()->end_tstamp().tv_nsec == 401994000);

    CHECK(dhcp_handler.metrics()->bucket(0)->period_length() == 30);

    json j;
    dhcp_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 8);
    CHECK(counters.filtered.value() == 0);
    CHECK(counters.DISCOVER.value() == 1);
    CHECK(counters.OFFER.value() == 1);
    CHECK(counters.REQUEST.value() == 3);
    CHECK(counters.ACK.value() == 3);

    CHECK(j["top_clients"][0]["name"] == "192.168.2.205/78:4f:43:78:19:bc/Shannons-MBP");
    CHECK(j["top_clients"][1]["name"] == "192.168.2.248/32:47:73:53:0e:3d/Zenfone-8");
}
