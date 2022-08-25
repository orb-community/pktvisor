/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "DnsWireStreamHandler.h"
#include "DnsXactStreamHandler.h"
#include "StreamHandler.h"
#include <Corrade/Utility/Debug.h>
#include <bitset>
#include <limits>
#include <string>

namespace visor::input::dnstap {
class DnstapInputEventProxy;
}

namespace visor::handler::dns {

static constexpr const char *DNS_SCHEMA{"dns"};

class DnsStreamHandler final : public visor::StreamHandler
{
    std::unique_ptr<DnsWireStreamHandler> _wire_dns;
    std::unique_ptr<DnsXactStreamHandler> _xact_dns;

public:
    DnsStreamHandler(const std::string &name, InputEventProxy *proxy, const Configurable *window_config)
        : StreamHandler(name)
    {
        _wire_dns = std::make_unique<DnsWireStreamHandler>(name, proxy, window_config);
        _xact_dns = std::make_unique<DnsXactStreamHandler>(name, proxy, window_config);
    }
    ~DnsStreamHandler() = default;

    DnsWireStreamHandler *wire_dns() const
    {
        return _wire_dns.get();
    }

    DnsXactStreamHandler *xact_dns() const
    {
        return _xact_dns.get();
    }

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return DNS_SCHEMA;
    }

    void start() override
    {
        if (_running) {
            return;
        }
        if (_event_proxy) {
            _wire_dns->set_event_proxy(std::move(_event_proxy));
        }
        _wire_dns->start();
        _xact_dns->start();
        _running = true;
    }

    void stop() override
    {
        if (!_running) {
            return;
        }
        _wire_dns->stop();
        _xact_dns->stop();
        _running = false;
    }

    void info_json(json &j) const override
    {
        _wire_dns->info_json(j);
    }

    void window_json(json &j, uint64_t period, bool merged) override
    {
        _wire_dns->window_json(j, period, merged);
        _xact_dns->window_json(j, period, merged);
    }

    void window_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) override
    {
        _wire_dns->window_prometheus(out, add_labels);
        _xact_dns->window_prometheus(out, add_labels);
    };
};
}
