#include <catch2/catch.hpp>

#include "GeoDB.h"
#include "PcapInputStream.h"
#include "PcapStreamHandler.h"

using namespace visor::handler::pcap;
using namespace visor::input::pcap;

TEST_CASE("Parse net (dns) random UDP/TCP tests", "[pcap][net]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
    stream.config_set("bpf", "");
    stream.config_set("host_spec", "192.168.0.0/24");
    stream.parse_host_spec();

    visor::Config c;
    auto stream_cb = stream.add_callback(c);
    c.config_set<uint64_t>("num_periods", 1);
    PcapStreamHandler pcap_handler{"pcap-handler-test", stream_cb, &c};

    pcap_handler.start();
    stream.start();
    stream.stop();
    pcap_handler.stop();

    auto counters = pcap_handler.metrics()->bucket(0)->counters();

    CHECK(pcap_handler.metrics()->start_tstamp().tv_sec == 1614874231);
    CHECK(pcap_handler.metrics()->start_tstamp().tv_nsec == 565771000);

    // confirmed with wireshark
    CHECK(counters.pcap_TCP_reassembly_errors.value() == 0);
    CHECK(counters.pcap_os_drop.value() == 0);
    CHECK(counters.pcap_if_drop.value() == 0);
}
