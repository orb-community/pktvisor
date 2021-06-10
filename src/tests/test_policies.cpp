#include "CoreRegistry.h"
#include "HandlerManager.h"
#include "InputModulePlugin.h"
#include "InputStream.h"
#include "InputStreamManager.h"
#include "MockInputStream.h"
#include "Policies.h"
#include "handlers/static_plugins.h"
#include <catch2/catch.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

using namespace visor;

auto collection_config = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  collection:
    # policy name and description
    default_view:
#      description: "a mock view of anycast traffic"
      # input stream to create based on the given tap and optional filter config
      input:
        # this must reference a tap name, or application of the policy will fail
        tap: anycast
        config:
          bpf: "tcp or udp"
      # stream handlers to attach to this input stream
      # these decide exactly which data to summarize and expose for collection
      handlers:
        # default configuration for the stream handlers
        window_config:
          num_periods: 5
          deep_sample_rate: 100
        modules:
          # the keys at this level are unique identifiers
          default_net:
            type: net
          default_dns:
            type: dns
#            window_config:
#              max_deep_sample: 75
          special_domain:
            type: dns
            config:
              qname_suffix: .mydomain.com
)";

auto collection_config_bad1 = R"(
visor:
  collection:
    missing:
)";

auto collection_config_bad2 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  collection:
    default_view:
      input:
        tap: nonexist
)";

auto collection_config_bad3 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  collection:
    default_view:
      input:
        tap: anycast
        config:
          bpf:
            badmap: "bad value"
)";

auto collection_config_bad4 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  collection:
    default_view:
      input:
        tap: anycast
        config:
          except_on_start: true
      handlers:
        modules:
          default_net:
            type: net
)";

TEST_CASE("Policies", "[policies]")
{

    SECTION("Good Config happy path")
    {
        CoreRegistry registry(nullptr);
        YAML::Node config_file = YAML::Load(collection_config);

        CHECK(config_file["visor"]["collection"]);
        CHECK(config_file["visor"]["collection"].IsMap());

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["collection"]));

        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        CHECK(policy->name() == "default_view");
        CHECK(policy->input_stream()->name() == "anycast-default_view");
        CHECK(policy->input_stream()->config_get<std::string>("bpf") == "tcp or udp");
        CHECK(policy->modules()[0]->name() == "default_view-default_net");
        CHECK(policy->modules()[1]->name() == "default_view-default_dns");
        CHECK(policy->modules()[2]->name() == "default_view-special_domain");
        CHECK(policy->modules()[2]->config_get<std::string>("qname_suffix") == ".mydomain.com");
        CHECK(!policy->input_stream()->running());
        CHECK(!policy->modules()[0]->running());
        // TODO check window config settings made it through
        CHECK(!policy->modules()[1]->running());
        CHECK(!policy->modules()[2]->running());
        REQUIRE_NOTHROW(policy->start());
        CHECK(policy->input_stream()->running());
        CHECK(policy->modules()[0]->running());
        CHECK(policy->modules()[1]->running());
        CHECK(policy->modules()[2]->running());
    }

    // TODO multiple collection policies in the same yaml

    SECTION("Duplicate")
    {
        CoreRegistry registry(nullptr);
        YAML::Node config_file = YAML::Load(collection_config);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["collection"]));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["collection"]), "policy creation failed (policy) default_view: module name 'default_view' already exists");

        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        CHECK(policy->name() == "default_view");
    }

    SECTION("Bad Config")
    {
        CoreRegistry registry(nullptr);
        YAML::Node config_file = YAML::Load(collection_config_bad1);

        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["collection"]), "expecting policy configuration map");
    }

    SECTION("Bad Config: invalid tap")
    {
        CoreRegistry registry(nullptr);
        YAML::Node config_file = YAML::Load(collection_config_bad2);

        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["collection"]), "tap 'nonexist' does not exist");
    }

    SECTION("Bad Config: invalid tap config")
    {
        CoreRegistry registry(nullptr);
        YAML::Node config_file = YAML::Load(collection_config_bad3);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["collection"]), "invalid input config for tap 'anycast': invalid value for key: bpf");
    }

    SECTION("Bad Config: exception on input start")
    {
        CoreRegistry registry(nullptr);
        YAML::Node config_file = YAML::Load(collection_config_bad4);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["collection"]));
        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        REQUIRE_THROWS_WITH(policy->start(), "mock error on start");
    }

    SECTION("Roll Back")
    {
        CoreRegistry registry(nullptr);
        YAML::Node config_file = YAML::Load(collection_config);

        CHECK(config_file["visor"]["collection"]);
        CHECK(config_file["visor"]["collection"].IsMap());

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));

        // force a roll back by creating a conflict with a handler module name that already exists
        Config config;
        auto input_stream = registry.input_plugins()["mock"]->instantiate("mymock", &config);
        auto mod = registry.handler_plugins()["net"]->instantiate("default_view-default_net", input_stream.get(), &config);
        registry.handler_manager()->module_add(std::move(mod));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["collection"]), "policy creation failed (handler: default_view-default_net) default_view: module name 'default_view-default_net' already exists");

        // ensure the modules were rolled back
        REQUIRE(!registry.policy_manager()->module_exists("default_view"));
        REQUIRE(!registry.input_manager()->module_exists("anycast-default_view"));
    }
}
