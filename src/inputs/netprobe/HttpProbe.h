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

using HttpResultCallback = std::function<void(visor::http::HttpSample, const std::string &, timespec)>;

class HttpProbe final : public NetProbe
{
    std::string _url;
    std::string _method;
    std::shared_ptr<visor::http::HttpClient> _client;
    HttpProbeOptions _opts;
    std::vector<std::string> _headers;
    long _ip_resolve{0};              // CURLOPT_IPRESOLVE override (0 => curl default); per-target ip_version
    std::vector<std::string> _resolve; // CURLOPT_RESOLVE entries, each "host:port:address"; per-target resolve
    HttpResultCallback _http_result;
    std::shared_ptr<uvw::timer_handle> _interval_timer;
    // CERTINFO is only populated on transfers that perform a TLS handshake; pooled-connection
    // reuse reports nothing. Cache the last known expiry so every sample carries it. shared_ptr so
    // the completion lambda can capture it BY VALUE (no `this` in completion lambdas — v1 contract)
    // while still sharing the same cell across ticks.
    std::shared_ptr<uint64_t> _cert_cache{std::make_shared<uint64_t>(0)};
    bool _init{false};

public:
    HttpProbe(uint16_t id, const std::string &name, std::string url, std::string method,
        std::shared_ptr<visor::http::HttpClient> client, HttpProbeOptions opts, std::vector<std::string> headers,
        long ip_resolve, std::vector<std::string> resolve,
        HttpResultCallback http_result)
        : NetProbe(id, name, pcpp::IPAddress(), std::string())
        , _url(std::move(url))
        , _method(std::move(method))
        , _client(std::move(client))
        , _opts(std::move(opts))
        , _headers(std::move(headers))
        , _ip_resolve(ip_resolve)
        , _resolve(std::move(resolve))
        , _http_result(std::move(http_result)) {}
    ~HttpProbe() = default;
    bool start(std::shared_ptr<uvw::loop> io_loop) override;
    bool stop() override;
};
}
