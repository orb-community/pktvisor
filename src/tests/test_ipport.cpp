#include "IpPort.h"

#include <catch2/catch_test_macros.hpp>

using namespace visor::network;

TEST_CASE("IpPort", "[ipport]")
{
    SECTION("Test Real file")
    {
        IpPort::ports_tcp_list.clear();
        IpPort::ports_udp_list.clear();
        CHECK_NOTHROW(IpPort::set_csv_iana_ports("tests/fixtures/service-names-port-numbers.csv"));
        IpPort test_tcp{53, Protocol::TCP};
        CHECK(test_tcp.get_service() == "domain");
        IpPort test_udp{53, Protocol::UDP};
        CHECK(test_udp.get_service() == "domain");
    }

    SECTION("test custom file")
    {
        IpPort::ports_tcp_list.clear();
        IpPort::ports_udp_list.clear();
        CHECK_NOTHROW(IpPort::set_csv_iana_ports("tests/fixtures/pktvisor-port-service-names.csv"));
        IpPort test_tcp{53, Protocol::TCP};
        CHECK(test_tcp.get_service() == "domain");
        IpPort test_tcp_range{11000, Protocol::TCP};
        CHECK(test_tcp_range.get_service() == "registered-10k");
        IpPort test_udp_range{25227, Protocol::UDP};
        CHECK(test_udp_range.get_service() == "registered-20k");
    }
}