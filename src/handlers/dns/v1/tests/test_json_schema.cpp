/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include <catch2/catch.hpp>
#include <fstream>
#include <nlohmann/json-schema.hpp>
#include <streambuf>
#include <string>

#include "PcapInputStream.h"
#include "DnsStreamHandler.h"

using namespace visor::handler::dns;
using namespace visor::input::pcap;
using namespace nlohmann;
using nlohmann::json_schema::json_validator;

TEST_CASE("DNS JSON Schema", "[dns][iface][json]")
{

    SECTION("json iface")
    {
        PcapInputStream stream{"pcap-test"};
        stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
        stream.config_set("bpf", "");
        stream.config_set("host_spec", "192.168.0.0/24");
        stream.parse_host_spec();

        visor::Config c;
        auto stream_proxy = stream.add_event_proxy(c);
        DnsStreamHandler dns_handler{"dns-test", stream_proxy, &c};
        dns_handler.config_set("recorded_stream", true);
        dns_handler.config_set<visor::Configurable::StringList>("enable", visor::Configurable::StringList({"top_ecs", "top_ports"}));

        dns_handler.start();
        stream.start();
        stream.stop();
        dns_handler.stop();

        json dns_json;
        dns_handler.metrics()->window_merged_json(dns_json, dns_handler.schema_key(), 5);

        std::ifstream sfile("handlers/dns/v1/tests/window-schema.json");
        CHECK(sfile.is_open());
        std::string schema;

        sfile.seekg(0, std::ios::end);
        schema.reserve(sfile.tellg());
        sfile.seekg(0, std::ios::beg);

        schema.assign((std::istreambuf_iterator<char>(sfile)), std::istreambuf_iterator<char>());
        json_validator validator;

        auto schema_json = json::parse(schema);

        try {
            validator.set_root_schema(schema_json);
            validator.validate(dns_json);
        } catch (const std::exception &e) {
            FAIL(e.what());
        }
    }
}
