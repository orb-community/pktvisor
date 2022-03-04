/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "InputStream.h"
#include "SflowData.h"
#include <sigslot/signal.hpp>
#include <spdlog/spdlog.h>
#include <uvw.hpp>

namespace visor::input::sflow {

class SflowInputStream : public visor::InputStream
{
    std::atomic<uint64_t> _error_count;
    std::shared_ptr<spdlog::logger> _logger;

    std::unique_ptr<std::thread> _io_thread;
    std::shared_ptr<uvw::Loop> _io_loop;
    std::shared_ptr<uvw::AsyncHandle> _async_h;

    std::shared_ptr<uvw::UDPHandle> _udp_server_h;

    void _read_from_pcap_file();
    void _create_frame_stream_udp_socket();
public:
    SflowInputStream(const std::string &name);
    ~SflowInputStream() = default;

    // visor::AbstractModule
    std::string schema_key() const override
    {
        return "sflow";
    }
    void start() override;
    void stop() override;
    void info_json(json &j) const override;
    size_t consumer_count() const override
    {
        return sflow_signal.slot_count();
    }

    // handler functionality
    // IF THIS changes, see consumer_count()
    // note: these are mutable because consumer_count() calls slot_count() which is not const (unclear if it could/should be)
    mutable sigslot::signal<const SFSample &> sflow_signal;
    std::vector<std::unique_ptr<CacheHandler>> cache_sflow_signal;
};

}
