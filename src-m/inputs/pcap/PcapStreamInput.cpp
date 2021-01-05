#include "PcapStreamInput.h"
#include <Corrade/PluginManager/AbstractManager.h>
#include <json/json.hpp>

using json = nlohmann::json;

CORRADE_PLUGIN_REGISTER(PcapInput, pktvisor::input::pcap::PcapStreamInput,
    "com.ns1.module.input/1.0")

namespace pktvisor {
namespace input {
namespace pcap {

void PcapStreamInput::_setup_routes(httplib::Server &svr)
{

    // CREATE
    svr.Post("/api/v1/input/pcap", [](const httplib::Request &req, httplib::Response &res) {
        auto error = R"(
  {
    "error": ""
  }
)"_json;
        auto success = R"(
  {
    "name": "",
    "success": true
  }
)"_json;
        try {
            auto body = json::parse(req.body);
            if (!body.contains("name")) {
                res.status = 400;
                error["error"] = "name is required";
                res.set_content(error.dump(), "text/json");
            }

            success["name"] = body["name"];
            res.set_content(success.dump(), "text/json");
        } catch (const std::exception &e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });
}

}
}
}