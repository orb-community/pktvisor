/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "InputStream.h"
#include "NetflowData.h"
#include "SflowData.h"
#include <spdlog/spdlog.h>
#include <uvw.hpp>

namespace visor::input::flow {

enum class Type {
    SFLOW,
    NETFLOW,
    UNKNOWN
};
class FlowInputStream : public visor::InputStream
{
    Type _flow_type;
    std::atomic<uint64_t> _error_count;
    std::shared_ptr<spdlog::logger> _logger;

    std::unique_ptr<std::thread> _io_thread;
    std::shared_ptr<uvw::Loop> _io_loop;
    std::shared_ptr<uvw::AsyncHandle> _async_h;
    std::shared_ptr<uvw::TimerHandle> _timer;

    std::shared_ptr<uvw::UDPHandle> _udp_server_h;

    void _read_from_pcap_file();
    void _create_frame_stream_udp_socket();

public:
    FlowInputStream(const std::string &name);
    ~FlowInputStream() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "flow";
    }
    void start() override;
    void stop() override;
    void info_json(json &j) const override;
    std::unique_ptr<InputCallback> create_callback(const Configurable &filter) override;
    size_t consumer_count() const override
    {
        return policy_signal.slot_count() + heartbeat_signal.slot_count() + sflow_signal.slot_count() + netflow_signal.slot_count();
    }

    // handler functionality
    // IF THIS changes, see consumer_count()
    // note: these are mutable because consumer_count() calls slot_count() which is not const (unclear if it could/should be)
    mutable sigslot::signal<const SFSample &> sflow_signal;
    mutable sigslot::signal<const NFSample &> netflow_signal;
};

class FlowInputStreamCallback : public visor::InputCallback
{
    FlowInputStream *_flow_stream{nullptr};

    sigslot::connection _sflow_connection;
    sigslot::connection _netflow_connection;
    sigslot::connection _heartbeat_connection;

    void _sflow_cb(const SFSample &sflow)
    {
        sflow_signal(sflow);
    }

    void _netflow_cb(const NFSample &netflow)
    {
        netflow_signal(netflow);
    }

    void _heartbeat_cb(timespec stamp)
    {
        heartbeat_signal(stamp);
    }

public:
    FlowInputStreamCallback(const Configurable &filter, FlowInputStream *flow)
        : InputCallback(filter)
    {
        _flow_stream = flow;
        _input_name = flow->name();
        _sflow_connection = _flow_stream->sflow_signal.connect(&FlowInputStreamCallback::_sflow_cb, this);
        _netflow_connection = _flow_stream->netflow_signal.connect(&FlowInputStreamCallback::_netflow_cb, this);
        _heartbeat_connection = _flow_stream->heartbeat_signal.connect(&FlowInputStreamCallback::_heartbeat_cb, this);
    }

    ~FlowInputStreamCallback()
    {
        if (_flow_stream) {
            _sflow_connection.disconnect();
            _netflow_connection.disconnect();
            _heartbeat_connection.disconnect();
        }
    }

    mutable sigslot::signal<const SFSample &> sflow_signal;
    mutable sigslot::signal<const NFSample &> netflow_signal;
    mutable sigslot::signal<const timespec> heartbeat_signal;
};

}
