#include "CoreManagers.h"
#include "InputModulePlugin.h"
#include <catch2/catch.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

using namespace visor;

auto tap_config = R"(
version: "1.0"

visor:
  config:
    verbose: true
  taps:
    wired:
      input_type: pcap
      config:
        iface: en7
        number: 123
        boolean: true
    wireless:
      input_type: pcap
      config:
        iface: en0
)";

auto tap_config_bad = R"(
version: "1.0"

visor:
  config:
    verbose: true
  taps:
    wired:
      input_type: nonexistent
      config:
        iface: en7
)";

TEST_CASE("Taps", "[taps]")
{

    SECTION("Good Config")
    {
        CoreManagers mgrs(nullptr);
        YAML::Node config_file = YAML::Load(tap_config);

        CHECK(config_file["visor"]["taps"]);
        CHECK(config_file["visor"]["taps"].IsMap());
        CHECK_NOTHROW(mgrs.tap_manager()->load(config_file["visor"]["taps"], true));

        auto [tap, lock] = mgrs.tap_manager()->module_get_locked("wired");
        CHECK(tap->name() == "wired");
        CHECK(tap->config_get<std::string>("iface") == "en7");
        CHECK(tap->config_get<uint64_t>("number") == 123);
        CHECK(tap->config_get<bool>("boolean") == true);
    }

    SECTION("Bad Config")
    {
        CoreManagers mgrs(nullptr);
        YAML::Node config_file = YAML::Load(tap_config_bad);

        CHECK(config_file["visor"]["taps"]);
        CHECK(config_file["visor"]["taps"].IsMap());
        CHECK_THROWS(mgrs.tap_manager()->load(config_file["visor"]["taps"], true));
    }
}
