#include "CoreRegistry.h"
#include "Labels.h"
#include <catch2/catch.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

using namespace visor;

auto label_config = R"(
version: "1.0"

visor:
  config:
    verbose: true
  labels:
    region: EU
    pop: ams02
    node_type: dns
)";

auto label_config_bad = R"(
version: "1.0"

visor:
  config:
    verbose: true
  labels:
    region:
     - EU
     - US
)";

TEST_CASE("Labels", "[labels]")
{

    SECTION("Good Config")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(label_config);

        CHECK(config_file["visor"]["labels"]);
        CHECK(config_file["visor"]["labels"].IsMap());
        CHECK_NOTHROW(registry.label_manager()->load(config_file["visor"]["labels"]));

        auto [label, lock] = registry.label_manager()->module_get_locked("region");
        CHECK(label->name() == "region");
        CHECK(label->value() == "EU");
    }

    SECTION("Duplicate")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(label_config);

        CHECK_NOTHROW(registry.label_manager()->load(config_file["visor"]["labels"]));
        CHECK_THROWS(registry.label_manager()->load(config_file["visor"]["labels"]));
    }

    SECTION("Bad Config")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(label_config_bad);

        CHECK(config_file["visor"]["labels"]);
        CHECK(config_file["visor"]["labels"].IsMap());
        CHECK_THROWS(registry.label_manager()->load(config_file["visor"]["labels"]));
    }
}
