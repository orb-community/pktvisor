/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "InputStream.h"
#include <spdlog/spdlog.h>
#include <timer.hpp>

namespace visor::input::mock {

class MockInputStream : public visor::InputStream
{

    std::shared_ptr<timer::interval_handle> _mock_work;
    std::shared_ptr<spdlog::logger> _logger;

public:
    MockInputStream(const std::string &name);
    ~MockInputStream();

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "mock";
    }
    void start() override;
    void stop() override;
    void info_json(json &j) const override;
    std::unique_ptr<InputEventProxy> create_event_proxy(const Configurable &filter) override;
};

class MockInputEventProxy : public visor::InputEventProxy
{

public:
    MockInputEventProxy(const std::string &name, const Configurable &filter)
        : InputEventProxy(name, filter)
    {
    }

    ~MockInputEventProxy() = default;

    size_t consumer_count() const override
    {
        return policy_signal.slot_count() + heartbeat_signal.slot_count() + random_int_signal.slot_count();
    }

    void random_int_cb(uint64_t value)
    {
        random_int_signal(value);
    }

    // handler functionality
    // IF THIS changes, see consumer_count()
    // note: these are mutable because consumer_count() calls slot_count() which is not const (unclear if it could/should be)
    mutable sigslot::signal<uint64_t> random_int_signal;
};

}
