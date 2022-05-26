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
    std::unique_ptr<InputCallback> create_callback(const Configurable &filter) override;
    size_t consumer_count() const override
    {
        return policy_signal.slot_count() + heartbeat_signal.slot_count() + random_int_signal.slot_count();
    }

    // handler functionality
    // IF THIS changes, see consumer_count()
    // note: these are mutable because consumer_count() calls slot_count() which is not const (unclear if it could/should be)
    mutable sigslot::signal<uint64_t> random_int_signal;
};

class MockInputStreamCallback : public visor::InputCallback
{
    MockInputStream *_mock_stream{nullptr};

    sigslot::connection _mock_connection;
    sigslot::connection _heartbeat_connection;
    sigslot::connection _policy_connection;

    void _random_int_cb(uint64_t value)
    {
        random_int_signal(value);
    }

    void _heartbeat_cb(timespec stamp)
    {
        heartbeat_signal(stamp);
    }

    void _policy_cb(const Policy *policy, Action action)
    {
        policy_signal(policy, action);
    }

public:
    MockInputStreamCallback(const Configurable &filter, MockInputStream *mock)
        : InputCallback(filter)
    {
        _mock_stream = mock;
        _input_name = mock->name();
        _mock_connection = _mock_stream->random_int_signal.connect(&MockInputStreamCallback::_random_int_cb, this);
        _heartbeat_connection = _mock_stream->heartbeat_signal.connect(&MockInputStreamCallback::_heartbeat_cb, this);
        _policy_connection = _mock_stream->policy_signal.connect(&MockInputStreamCallback::_policy_cb, this);
    }

    ~MockInputStreamCallback()
    {
        if (_mock_stream) {
            _mock_connection.disconnect();
            _heartbeat_connection.disconnect();
            _policy_connection.disconnect();
        }
    }

    mutable sigslot::signal<uint64_t> random_int_signal;
    mutable sigslot::signal<const timespec> heartbeat_signal;
    mutable sigslot::signal<const Policy *, Action> policy_signal;
};

}
