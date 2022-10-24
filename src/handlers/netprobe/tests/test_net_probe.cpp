#include <catch2/catch.hpp>

#include "NetProbeInputStream.h"
#include "NetProbeStreamHandler.h"

using namespace visor::handler::netprobe;
using namespace visor::input::netprobe;
using namespace std::chrono;
using namespace nlohmann;

TEST_CASE("Parse Net Probe tests", "[pcap][netprobe]")
{
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "ping");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "localhost");
    targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto stream_proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler netprobe_handler{"net-probe-test", stream_proxy, &c};

    netprobe_handler.start();
    stream.start();
    std::this_thread::sleep_for(1s);
    netprobe_handler.stop();
    stream.stop();

    auto event_data = netprobe_handler.metrics()->bucket(0)->event_data_locked();

    CHECK(netprobe_handler.metrics()->current_periods() == 1);
    CHECK(netprobe_handler.metrics()->bucket(0)->period_length() == 1);

    json j;
    netprobe_handler.metrics()->bucket(0)->to_json(j);

    CHECK(event_data.num_events->value() >= 1);
    CHECK(j["targets"]["my_target"]["attempts"] >= 1);
}
