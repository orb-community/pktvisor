#include "CoreRegistry.h"
#include "Taps.h"
#include <catch2/catch.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

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
      tags:
        number: 123
        boolean: true
        string: "value"
    wireless:
      input_type: pcap
      config:
        iface: en0
      tags:
        string: "value"
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
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(tap_config);

        CHECK(config_file["visor"]["taps"]);
        CHECK(config_file["visor"]["taps"].IsMap());
        CHECK_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));

        auto [tap, lock] = registry.tap_manager()->module_get_locked("wired");
        CHECK(tap->name() == "wired");
        CHECK(tap->config_get<std::string>("iface") == "en7");
        CHECK(tap->config_get<uint64_t>("number") == 123);
        CHECK(tap->config_get<bool>("boolean") == true);
    }

    SECTION("Duplicate")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(tap_config);

        CHECK_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        CHECK_THROWS(registry.tap_manager()->load(config_file["visor"]["taps"], true));
    }

    SECTION("Bad Config")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(tap_config_bad);

        CHECK(config_file["visor"]["taps"]);
        CHECK(config_file["visor"]["taps"].IsMap());
        CHECK_THROWS(registry.tap_manager()->load(config_file["visor"]["taps"], true));
    }

    SECTION("Json validation")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(tap_config);

        CHECK(config_file["visor"]["taps"]);
        CHECK(config_file["visor"]["taps"].IsMap());
        CHECK_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        auto [tap, lock] = registry.tap_manager()->module_get_locked("wired");
        CHECK(tap->name() == "wired");

        json j;
        tap->info_json(j);

        CHECK(j["input_type"] == "pcap");
        CHECK(j["config"]["boolean"] == true);
        CHECK(j["config"]["number"] == 123);
        CHECK(j["config"]["iface"] == "en7");
        CHECK(j["tags"]["boolean"] == true);
        CHECK(j["tags"]["number"] == 123);
        CHECK(j["tags"]["string"] == "value");
    }
}
