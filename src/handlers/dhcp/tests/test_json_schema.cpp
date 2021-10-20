/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include <catch2/catch.hpp>
#include <fstream>
#include <nlohmann/json-schema.hpp>
#include <streambuf>
#include <string>

#include "PcapInputStream.h"
#include "DhcpStreamHandler.h"

using namespace visor::handler::dhcp;
using namespace visor::input::pcap;
using namespace nlohmann;
using nlohmann::json_schema::json_validator;

TEST_CASE("DHCP JSON Schema", "[dhcp][iface][json]")
{

    SECTION("json iface")
    {

        PcapInputStream stream{"pcap-test"};
        stream.config_set("pcap_file", "tests/fixtures/dhcp_ipv4.pcap");
        stream.config_set("bpf", "");
        stream.config_set("host_spec", "192.168.0.0/24");
        stream.parse_host_spec();

        visor::Config c;
        DhcpStreamHandler handler{"dhcp-test", &stream, &c};
        handler.config_set("recorded_stream", true);

        handler.start();
        stream.start();
        stream.stop();
        handler.stop();

        json pcap_json;
        handler.metrics()->window_merged_json(pcap_json, handler.schema_key(), 5);
        WARN(pcap_json);
        std::ifstream sfile("handlers/dhcp/tests/window-schema.json");
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
            validator.validate(pcap_json);
        } catch (const std::exception &e) {
            FAIL(e.what());
        }
    }
}
