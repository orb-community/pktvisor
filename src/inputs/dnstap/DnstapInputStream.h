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

    void _read_frame_stream_file();
    void _create_frame_stream_unix_socket();
    void _create_frame_stream_tcp_socket();

    inline bool _filtering([[maybe_unused]] const ::dnstap::Dnstap &d)
    {
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
    std::unique_ptr<InputEventProxy> create_event_proxy(const Configurable &filter) override;
};

}
