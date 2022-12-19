/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "visor_config.h"
#include <functional>
#include <timer.hpp>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include <httplib.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include "opentelemetry/proto/collector/metrics/v1/metrics_service.pb.h"

namespace visor {

constexpr char BIN_CONTENT_TYPE[] = "application/x-protobuf";

using namespace opentelemetry::proto;

struct OtelConfig {
    bool enable{false};
    std::string endpoint{"localhost"};
    uint32_t port_number{4317};
    uint64_t interval_sec{60};
    std::string tls_cert;
    std::string tls_key;
};

class OpenTelemetry
{
    httplib::Client _client;
    collector::metrics::v1::ExportMetricsServiceRequest _request;
    metrics::v1::ScopeMetrics *_scope;
    std::shared_ptr<timer::interval_handle> _timer_handle;
    std::function<bool(metrics::v1::ScopeMetrics &scope)> _callback;

public:
    OpenTelemetry(const OtelConfig &config)
        : _client(config.endpoint, config.port_number)
    {
        auto resource = _request.add_resource_metrics();
        _scope = resource->add_scope_metrics();
        _scope->mutable_scope()->set_name("pktvisor");
        _scope->mutable_scope()->set_version(VISOR_VERSION_NUM);
        static timer timer_thread{std::chrono::seconds(config.interval_sec)};
        _timer_handle = timer_thread.set_interval(std::chrono::seconds(config.interval_sec), [this] {
            _scope->clear_metrics();
            if (_callback && _callback(*_scope)) {
                if (auto body_size = _request.ByteSizeLong(); _scope->metrics_size()) {
                    auto body = std::make_unique<char[]>(body_size);
                    _request.SerializeToArray(body.get(), body_size);
                    auto result = _client.Post("/v1/metrics", body.get(), body_size, BIN_CONTENT_TYPE);
                }
            }
        });
    }

    ~OpenTelemetry()
    {
        _timer_handle->cancel();
        _scope->clear_scope();
        _scope = nullptr;
    }

    void OnInterval(std::function<bool(metrics::v1::ScopeMetrics &scope)> callback)
    {
        _callback = callback;
    }
};
}