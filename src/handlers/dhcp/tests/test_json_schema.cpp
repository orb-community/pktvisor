/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include <catch2/catch.hpp>
#include <fstream>
#include <nlohmann/json-schema.hpp>
#include <streambuf>
#include <string>

#include "PcapInputStream.h"
#include "PcapStreamHandler.h"

using namespace visor::handler::pcap;
using namespace visor::input::pcap;
using namespace nlohmann;
using nlohmann::json_schema::json_validator;

TEST_CASE("Pcap JSON Schema", "[pcap][iface][json]")
{

    SECTION("json iface")
    {

        PcapInputStream stream{"pcap-test"};
        stream.config_set("pcap_file", "tests/fixtures/dns_udp_tcp_random.pcap");
        stream.config_set("bpf", "");
        stream.config_set("host_spec", "192.168.0.0/24");
        stream.parse_host_spec();

        visor::Config c;
        PcapStreamHandler pcap_handler{"pcap-test", &stream, &c};
        pcap_handler.config_set("recorded_stream", true);

        pcap_handler.start();
        stream.start();
        stream.stop();
        pcap_handler.stop();

        json pcap_json;
        pcap_handler.metrics()->window_merged_json(pcap_json, pcap_handler.schema_key(), 5);
        WARN(pcap_json);
        std::ifstream sfile("handlers/pcap/tests/window-schema.json");
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
