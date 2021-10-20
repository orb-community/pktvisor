#include <catch2/catch.hpp>

#include "PcapInputStream.h"
#include "DhcpStreamHandler.h"

using namespace visor::handler::dhcp;
using namespace visor::input::pcap;
using namespace nlohmann;

TEST_CASE("Parse DHCP tests", "[pcap][dhcp]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/nb6-startup.pcap");
    stream.config_set("bpf", "");

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    DhcpStreamHandler dhcp_handler{"dhcp-test", &stream, &c};

    dhcp_handler.start();
    stream.start();
    dhcp_handler.stop();
    stream.stop();

    auto counters = dhcp_handler.metrics()->bucket(0)->counters();
    auto event_data = dhcp_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(dhcp_handler.metrics()->current_periods() == 1);
    CHECK(dhcp_handler.metrics()->start_tstamp().tv_sec == 54);
    CHECK(dhcp_handler.metrics()->start_tstamp().tv_nsec == 643990000);

    CHECK(dhcp_handler.metrics()->end_tstamp().tv_sec == 1388651332);
    CHECK(dhcp_handler.metrics()->end_tstamp().tv_nsec == 306235000);

    CHECK(dhcp_handler.metrics()->bucket(0)->period_length() == 1388651278);

    json j;
    dhcp_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() == 11);
    CHECK(counters.DISCOVER.value() == 7);
    CHECK(counters.OFFER.value() == 2);
    CHECK(counters.REQUEST.value() == 1);
    CHECK(counters.ACK.value() == 1);

}
