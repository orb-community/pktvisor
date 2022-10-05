/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "InputStream.h"
#include "ICMPSocket.h"
#include <spdlog/spdlog.h>
#include <uvw.hpp>

namespace visor::input::netprobe {

class NetProbeInputStream : public visor::InputStream
{
    std::atomic<uint64_t> _error_count;
    std::shared_ptr<spdlog::logger> _logger;

    std::unique_ptr<std::thread> _io_thread;
    std::shared_ptr<uvw::Loop> _io_loop;
    std::shared_ptr<uvw::AsyncHandle> _async_h;
    std::shared_ptr<uvw::TimerHandle> _timer;

    std::unique_ptr<network::ICMPSocket> _icmp;

public:
    NetProbeInputStream(const std::string &name);
    ~NetProbeInputStream() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "netprobe";
    }
    void start() override;
    void stop() override;
    void info_json(json &j) const override;
    std::unique_ptr<InputEventProxy> create_event_proxy(const Configurable &filter) override;
};

class NetProbeInputEventProxy : public visor::InputEventProxy
{
public:
    NetProbeInputEventProxy(const std::string &name, const Configurable &filter)
        : InputEventProxy(name, filter)
    {
    }

    ~NetProbeInputEventProxy() = default;

    size_t consumer_count() const override
    {
        return policy_signal.slot_count() + heartbeat_signal.slot_count();
    }
};

}
