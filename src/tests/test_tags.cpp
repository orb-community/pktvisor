#include "CoreRegistry.h"
#include "Tags.h"
#include <catch2/catch.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

using namespace visor;

auto tag_config = R"(
version: "1.0"

visor:
  config:
    verbose: true
  tags:
    region: EU
    pop: ams02
    node_type: dns
)";

auto tag_config_bad = R"(
version: "1.0"

visor:
  config:
    verbose: true
  tags:
    region:
     - EU
     - US
)";

TEST_CASE("Tags", "[tags]")
{

    SECTION("Good Config")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(tag_config);

        CHECK(config_file["visor"]["tags"]);
        CHECK(config_file["visor"]["tags"].IsMap());
        CHECK_NOTHROW(registry.tag_manager()->load(config_file["visor"]["tags"]));

        auto [tag, lock] = registry.tag_manager()->module_get_locked("region");
        CHECK(tag->name() == "region");
        CHECK(tag->value() == "EU");
    }

    SECTION("Duplicate")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(tag_config);

        CHECK_NOTHROW(registry.tag_manager()->load(config_file["visor"]["tags"]));
        CHECK_THROWS(registry.tag_manager()->load(config_file["visor"]["tags"]));
    }

    SECTION("Bad Config")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(tag_config_bad);

        CHECK(config_file["visor"]["tags"]);
        CHECK(config_file["visor"]["tags"].IsMap());
        CHECK_THROWS(registry.tag_manager()->load(config_file["visor"]["tags"]));
    }
}
