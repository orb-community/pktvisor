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

auto policies_config = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    # policy name and description
    default_view:
      kind: collection
#      description: "a mock view of anycast traffic"
      # input stream to create based on the given tap and optional filter config
      input:
        # this must reference a tap name, or application of the policy will fail
        tap: anycast
        input_type: mock
        config:
          sample: value
        filter:
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
            filter:
              only_qname_suffix:
                - ".google.com"
                - ".ns1.com"
                - "slack.com"
)";

auto policies_config_bad1 = R"(
visor:
  policies:
    missing:
)";

auto policies_config_bad2 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      input:
        tap: nonexist
        input_type: mock
)";

auto policies_config_bad3 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
        filter:
          bpf:
            badmap: "bad value"
)";

auto policies_config_bad4 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: mock
        config:
          except_on_start: true
      handlers:
        modules:
          default_net:
            type: net
)";
auto policies_config_bad5 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: collection
      input:
        tap: anycast
        input_type: wrong_type
)";
auto policies_config_bad6 = R"(
version: "1.0"

visor:
  taps:
    anycast:
      input_type: mock
      config:
        iface: eth0
  policies:
    default_view:
      kind: unknown_kind
      input:
        tap: anycast
        input_type: mock
)";

TEST_CASE("Policies", "[policies]")
{

    SECTION("Good Config happy path")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config);

        CHECK(config_file["visor"]["policies"]);
        CHECK(config_file["visor"]["policies"].IsMap());

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));

        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        CHECK(policy->name() == "default_view");
        CHECK(policy->input_stream()->name() == "anycast-default_view");
        CHECK(policy->input_stream()->config_get<std::string>("bpf") == "tcp or udp"); // TODO this will move to filter member variable
        CHECK(policy->input_stream()->config_get<std::string>("sample") == "value");
        CHECK(policy->modules()[0]->name() == "default_view-default_net");
        CHECK(policy->modules()[1]->name() == "default_view-default_dns");
        CHECK(policy->modules()[2]->name() == "default_view-special_domain");
        CHECK(policy->modules()[2]->config_get<Configurable::StringList>("only_qname_suffix")[0] == ".google.com");
        // TODO check window config settings made it through
        CHECK(policy->input_stream()->running());
        CHECK(policy->modules()[0]->running());
        CHECK(policy->modules()[1]->running());
        CHECK(policy->modules()[2]->running());
    }

    // TODO multiple collection policies in the same yaml

    SECTION("Duplicate")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "policy with name 'default_view' already defined");

        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        CHECK(policy->name() == "default_view");
    }

    SECTION("Bad Config")
    {
        CoreRegistry registry;
        YAML::Node config_file = YAML::Load(policies_config_bad1);

        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "expecting policy configuration map");
    }

    SECTION("Bad Config: invalid tap")
    {
        CoreRegistry registry;
        YAML::Node config_file = YAML::Load(policies_config_bad2);

        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "tap 'nonexist' does not exist");
    }

    SECTION("Bad Config: invalid tap config")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad3);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "invalid input filter for tap 'anycast': invalid value for key: bpf");
    }

    SECTION("Bad Config: exception on input start")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad4);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "policy [default_view] failed to start: mock error on start");
    }

    SECTION("Bad Config: mis-matched input_type on tap")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad5);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "unable to instantiate tap 'anycast': input_type for policy specified tap 'anycast' doesn't match tap's defined input type: wrong_type/mock");
    }

    SECTION("Bad Config: bad policy kind")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config_bad6);

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "unknown policy kind: unknown_kind");
    }

    SECTION("Roll Back")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config);

        CHECK(config_file["visor"]["policies"]);
        CHECK(config_file["visor"]["policies"].IsMap());

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));

        // force a roll back by creating a conflict with a handler module name that already exists
        Config config;
        auto input_stream = registry.input_plugins()["mock"]->instantiate("mymock", &config);
        auto mod = registry.handler_plugins()["net"]->instantiate("default_view-default_net", input_stream.get(), &config);
        registry.handler_manager()->module_add(std::move(mod));
        REQUIRE_THROWS_WITH(registry.policy_manager()->load(config_file["visor"]["policies"]), "policy [default_view-default_net] creation failed (handler: default_view): module name 'default_view-default_net' already exists");

        // ensure the modules were rolled back
        REQUIRE(!registry.policy_manager()->module_exists("default_view"));
        REQUIRE(!registry.input_manager()->module_exists("anycast-default_view"));
    }
    SECTION("Good Config, test stop()")
    {
        CoreRegistry registry;
        registry.start(nullptr);
        YAML::Node config_file = YAML::Load(policies_config);

        CHECK(config_file["visor"]["policies"]);
        CHECK(config_file["visor"]["policies"].IsMap());

        REQUIRE_NOTHROW(registry.tap_manager()->load(config_file["visor"]["taps"], true));
        REQUIRE_NOTHROW(registry.policy_manager()->load(config_file["visor"]["policies"]));

        REQUIRE(registry.policy_manager()->module_exists("default_view"));
        auto [policy, lock] = registry.policy_manager()->module_get_locked("default_view");
        CHECK(policy->name() == "default_view");
        CHECK(policy->input_stream()->running());
        CHECK(policy->modules()[0]->running());
        CHECK(policy->modules()[1]->running());
        CHECK(policy->modules()[2]->running());
        policy->stop();
        CHECK(!policy->input_stream()->running());
        CHECK(!policy->modules()[0]->running());
        CHECK(!policy->modules()[1]->running());
        CHECK(!policy->modules()[2]->running());
        lock.unlock();
        REQUIRE_NOTHROW(registry.policy_manager()->module_remove("default_view"));
    }
}
