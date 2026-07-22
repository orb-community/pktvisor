/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once
#include "HttpClient.h"
#include "HttpProbeOptions.h"
#include "NetProbe.h"
#include <functional>
#include <memory>
#include <uvw/timer.h>

namespace visor::input::netprobe {

// http_status, rcode, parse_ok, cert_expiry_epoch, timings, name, stamp
using DohResultCallback = std::function<void(uint16_t, uint8_t, bool, uint64_t, visor::http::HttpTimings, const std::string &, timespec)>;

class DohProbe final : public NetProbe
{
    std::string _url;
    std::string _method;     // "POST" or "GET"
    std::string _qname;
    std::string _qtype;      // e.g. "A"
    std::shared_ptr<visor::http::HttpClient> _client;
    HttpProbeOptions _opts;  // uses only proxy/tls/user_agent + collect_cert_info
    long _ip_resolve{0};              // CURLOPT_IPRESOLVE override (0 => curl default); per-target ip_version
    std::vector<std::string> _resolve; // CURLOPT_RESOLVE entries, each "host:port:address"; per-target resolve
    DohResultCallback _doh_result;
    std::shared_ptr<uvw::timer_handle> _interval_timer;
    std::string _query_wire; // pre-built DNS query (wire format), built in start()
    std::string _get_url;    // pre-built URL with ?dns=<base64url> for GET
    uint16_t _qtype_code{0}; // numeric DNS qtype (from QTypeNumbers), for response question validation
    std::string _wire_qname; // qname as pcpp encodes/decodes it: "" for the root ("."), else _qname
    // Same cert-expiry cache contract as HttpProbe (see there for the rationale).
    std::shared_ptr<uint64_t> _cert_cache{std::make_shared<uint64_t>(0)};
    bool _init{false};

public:
    DohProbe(uint16_t id, const std::string &name, std::string url, std::string method,
        std::string qname, std::string qtype,
        std::shared_ptr<visor::http::HttpClient> client, HttpProbeOptions opts,
        long ip_resolve, std::vector<std::string> resolve, DohResultCallback doh_result)
        : NetProbe(id, name, pcpp::IPAddress(), std::string())
        , _url(std::move(url))
        , _method(std::move(method))
        , _qname(std::move(qname))
        , _qtype(std::move(qtype))
        , _client(std::move(client))
        , _opts(std::move(opts))
        , _ip_resolve(ip_resolve)
        , _resolve(std::move(resolve))
        , _doh_result(std::move(doh_result)) {}
    ~DohProbe() = default;
    bool start(std::shared_ptr<uvw::loop> io_loop) override;
    bool stop() override;
};
}
