/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "FrameSession.h"
#include "InputStream.h"
#include "dnstap.pb.h"
#include <DnsLayer.h>
#include <spdlog/spdlog.h>
#include <unordered_map>
#include <uv.h>

namespace uvw {
class Loop;
class AsyncHandle;
class PipeHandle;
class TCPHandle;
class TimerHandle;
}

struct fstrm_reader;

namespace visor::input::dnstap {

typedef std::pair<in_addr, uint8_t> Ipv4Subnet;
typedef std::pair<in6_addr, uint8_t> Ipv6Subnet;

const static std::string CONTENT_TYPE = "protobuf:dnstap.Dnstap";

class DnstapInputStream : public visor::InputStream
{
    std::shared_ptr<spdlog::logger> _logger;

    std::unique_ptr<std::thread> _io_thread;
    std::shared_ptr<uvw::Loop> _io_loop;
    std::shared_ptr<uvw::AsyncHandle> _async_h;
    std::shared_ptr<uvw::TimerHandle> _timer;

    std::shared_ptr<uvw::PipeHandle> _unix_server_h;
    std::unordered_map<uv_os_fd_t, std::unique_ptr<FrameSessionData<uvw::PipeHandle>>> _unix_sessions;

    std::shared_ptr<uvw::TCPHandle> _tcp_server_h;
    std::unordered_map<uv_os_fd_t, std::unique_ptr<FrameSessionData<uvw::TCPHandle>>> _tcp_sessions;

    std::vector<Ipv4Subnet> _IPv4_host_list;
    std::vector<Ipv6Subnet> _IPv6_host_list;

    enum Filters {
        OnlyHosts,
        FiltersMAX
    };
    std::bitset<Filters::FiltersMAX> _f_enabled;

    void _read_frame_stream_file();
    void _create_frame_stream_unix_socket();
    void _create_frame_stream_tcp_socket();

    void _parse_host_specs(const std::vector<std::string> &host_list);
    bool _match_subnet(const std::string &dnstap_ip);

    inline bool _filtering(const ::dnstap::Dnstap &d)
    {
        if (_f_enabled[Filters::OnlyHosts]) {
            if (d.message().has_query_address() && d.message().has_response_address()) {
                if (!_match_subnet(d.message().query_address()) && !_match_subnet(d.message().response_address())) {
                    // message had both query and response address, and neither matched, so filter
                    return true;
                }
            } else if (d.message().has_query_address() && !_match_subnet(d.message().query_address())) {
                // message had only query address and it didn't match, so filter
                return true;
            } else if (d.message().has_response_address() && !_match_subnet(d.message().response_address())) {
                // message had only response address and it didn't match, so filter
                return true;
            } else {
                // message had neither query nor response address, so filter
                return true;
            }
        }

        return false;
    }

public:
    DnstapInputStream(const std::string &name);
    ~DnstapInputStream() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "dnstap";
    }
    void start() override;
    void stop() override;
    void info_json(json &j) const override;
    std::unique_ptr<InputCallback> create_callback(const Configurable &filter) override;
    size_t consumer_count() const override
    {
        return policy_signal.slot_count() + heartbeat_signal.slot_count() + dnstap_signal.slot_count();
    }

    // handler functionality
    // IF THIS changes, see consumer_count()
    // note: these are mutable because consumer_count() calls slot_count() which is not const (unclear if it could/should be)
    mutable sigslot::signal<const ::dnstap::Dnstap &, size_t> dnstap_signal;
};

class DnstapInputStreamCallback : public visor::InputCallback
{
    DnstapInputStream *_dnstap_stream{nullptr};

    sigslot::connection _dnstap_connection;
    sigslot::connection _heartbeat_connection;
    sigslot::connection _policy_connection;

    void _dnstap_cb(const ::dnstap::Dnstap &dnstap, size_t size)
    {
        dnstap_signal(dnstap, size);
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
    DnstapInputStreamCallback(const Configurable &filter, DnstapInputStream *dnstap)
        : InputCallback(filter)
    {
        _dnstap_stream = dnstap;
        _input_name = dnstap->name();
        _dnstap_connection = _dnstap_stream->dnstap_signal.connect(&DnstapInputStreamCallback::_dnstap_cb, this);
        _heartbeat_connection = _dnstap_stream->heartbeat_signal.connect(&DnstapInputStreamCallback::_heartbeat_cb, this);
        _policy_connection = _dnstap_stream->policy_signal.connect(&DnstapInputStreamCallback::_policy_cb, this);
    }

    ~DnstapInputStreamCallback()
    {
        if (_dnstap_stream) {
            _dnstap_connection.disconnect();
            _heartbeat_connection.disconnect();
            _policy_connection.disconnect();
        }
    }

    mutable sigslot::signal<const ::dnstap::Dnstap &, size_t> dnstap_signal;
    mutable sigslot::signal<const timespec> heartbeat_signal;
    mutable sigslot::signal<const Policy *, Action> policy_signal;
};

}
