#include "CoreRegistry.h"
#include "InputModulePlugin.h"
#include <catch2/catch.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

using namespace visor;

auto collection_config = R"(
version: "1.0"

visor:
  taps:
    wired:
      input_type: pcap
      config:
        iface: en7
  collection:
    # policy name and description
    wired_view:
      description: "a view of wired traffic"
      # input stream to create based on the given tap and optional filter config
      input:
        # this must reference a tap name, or application of the policy will fail
        tap: wired
        filter:
          bpf: "tcp or udp"
      # stream handlers to attach to this input stream
      # these decide exactly which data to summarize and expose for collection
      handlers:
        # default configuration for the stream handlers
        config:
          max_deep_sample: 95
        modules:
          # the keys at this level are unique identifiers
          default_net:
            type: net
          udp_traffic:
            type: net
            config:
              protocols: [ udp ]
#            metrics:
#              enable:
#                - top_ips
          default_dns:
            type: dns
            config:
              max_deep_sample: 75
          special_domain:
            type: dns
#            # specify that the stream handler module requires >= specific version to be successfully applied
#            require_version: "1.0"
            config:
              # must match the available configuration options for this version of this stream handler
              qname_suffix: .mydomain.com
#            metrics:
#              disable:
#                - top_qtypes
#                - top_udp_ports
)";

auto collection_config_bad = R"(
visor:
  collection:
    missing:
)";

TEST_CASE("Policies", "[policies]")
{

    SECTION("Good Config")
    {
        CoreRegistry mgrs(nullptr);
        YAML::Node config_file = YAML::Load(collection_config);

        CHECK(config_file["visor"]["collection"]);
        CHECK(config_file["visor"]["collection"].IsMap());
        CHECK_NOTHROW(mgrs.policy_manager()->load(config_file["visor"]["collection"], true));

        auto [policy, lock] = mgrs.policy_manager()->module_get_locked("wired_view");
        CHECK(policy->name() == "wired_view");
        CHECK(policy->tap_filter()["bpf"].as<std::string>() == "tcp or udp");
    }

    SECTION("Bad Config")
    {
        CoreRegistry mgrs(nullptr);
        YAML::Node config_file = YAML::Load(collection_config_bad);

        CHECK(config_file["visor"]["collection"]);
        CHECK(config_file["visor"]["collection"].IsMap());
        CHECK_THROWS(mgrs.policy_manager()->load(config_file["visor"]["collection"], true));
    }

    SECTION("Policy Apply")
    {
        CoreRegistry mgrs(nullptr);
        YAML::Node config_file = YAML::Load(collection_config);

        CHECK_NOTHROW(mgrs.policy_manager()->load(config_file["visor"]["collection"], true));

        auto [policy, lock] = mgrs.policy_manager()->module_get_locked("wired_view");
        CHECK_NOTHROW(policy->apply(mgrs.tap_manager()));
    }
}
