/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "InputStream.h"
#include "dnstap.pb.h"
#include <DnsLayer.h>
#include <sigslot/signal.hpp>
#include <spdlog/spdlog.h>

namespace uvw {
class Loop;
class AsyncHandle;
}

struct fstrm_reader;

namespace visor::input::dnstap {

const static std::string CONTENT_TYPE = "protobuf:dnstap.Dnstap";

class DnstapException : public std::runtime_error
{
public:
    DnstapException(const char *msg)
        : std::runtime_error(msg)
    {
    }
};

class FrameSessionData final
{
public:
    using on_data_frame_cb_t = std::function<void(const void *data, std::size_t size)>;
    using on_frame_stream_err_cb_t = std::function<void(const std::string &err)>;
    using on_control_ready_cb_t = std::function<bool()>;
    using on_control_finished_cb_t = std::function<bool()>;

    enum class FrameState {
        New,
        Ready,
        Running,
        Finishing
    };

private:
    std::string _content_type;
    std::string _buffer;
    bool _is_bidir;

    on_data_frame_cb_t _on_data_frame_cb;
    on_frame_stream_err_cb_t _on_frame_stream_err_cb;
    on_control_ready_cb_t _on_control_ready_cb;
    on_control_finished_cb_t _on_control_finished_cb;

    FrameState _state{FrameState::New};

    bool decode_control_frame(const void *control_frame, size_t len_control_frame);

public:
    FrameSessionData(
        const std::string &content_type,
        on_data_frame_cb_t on_data_frame,
        on_frame_stream_err_cb_t on_frame_stream_err,
        on_control_ready_cb_t on_control_ready,
        on_control_finished_cb_t on_control_finished)
        : _content_type{content_type}
        , _on_data_frame_cb{std::move(on_data_frame)}
        , _on_frame_stream_err_cb{std::move(on_frame_stream_err)}
        , _on_control_ready_cb(std::move(on_control_ready))
        , _on_control_finished_cb(std::move(on_control_finished))
    {
    }

    bool receive_socket_data(const char data[], std::size_t data_len);

    const FrameState &state() const
    {
        return _state;
    }

    bool is_bidir() const
    {
        return _is_bidir;
    }
};

class DnstapInputStream : public visor::InputStream
{
    std::shared_ptr<spdlog::logger> _logger;

    std::unique_ptr<std::thread> _io_thread;
    std::shared_ptr<uvw::Loop> _io_loop;
    std::shared_ptr<uvw::AsyncHandle> _async_h;

    void _read_frame_stream_file();
    void _create_frame_stream_socket();

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
    size_t consumer_count() const override
    {
        return dnstap_signal.slot_count();
    }

    // handler functionality
    // IF THIS changes, see consumer_count()
    // note: these are mutable because consumer_count() calls slot_count() which is not const (unclear if it could/should be)
    mutable sigslot::signal<const ::dnstap::Dnstap &> dnstap_signal;
};

}
