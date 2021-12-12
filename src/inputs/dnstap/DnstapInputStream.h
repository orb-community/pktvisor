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

class DnstapException : public std::runtime_error
{
public:
    DnstapException(const char *msg)
        : std::runtime_error(msg)
    {
    }
    DnstapException(const std::string &msg)
        : std::runtime_error(msg)
    {
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
    mutable sigslot::signal<const ::dnstap::Dnstap&> dnstap_signal;
};

}
