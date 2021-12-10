/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DnstapInputStream.h"
#include <fstrm/fstrm.h>
#include <uvw/async.h>
#include <uvw/loop.h>

namespace visor::input::dnstap {

DnstapInputStream::DnstapInputStream(const std::string &name)
    : visor::InputStream(name)
{
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    _logger = spdlog::get("visor");
    assert(_logger);
}

void DnstapInputStream::_read_frame_stream()
{

    // Setup file reader options
    struct fstrm_file_options *fopt;
    fopt = fstrm_file_options_init();
    assert(config_exists("dnstap_file"));
    fstrm_file_options_set_file_path(fopt, config_get<std::string>("dnstap_file").c_str());

    // Initialize file reader
    struct fstrm_reader *r = fstrm_file_reader_init(fopt, nullptr);
    if (!r) {
        throw DnstapException("fstrm_file_reader_init() failed");
    }
    fstrm_res res = fstrm_reader_open(r);
    if (res != fstrm_res_success) {
        throw DnstapException("fstrm_reader_open() failed");
    }

    // Cleanup
    fstrm_file_options_destroy(&fopt);

    // Loop over data frames
    for (;;) {
        const uint8_t *data;
        size_t len_data;

        res = fstrm_reader_read(r, &data, &len_data);
        if (res == fstrm_res_success) {
            // Data frame ready, parse protobuf
            ::dnstap::Dnstap d;
            if (!d.ParseFromArray(data, len_data)) {
                _logger->warn("Dnstap::ParseFromArray fail, skipping frame of size {}", len_data);
                continue;
            }
            if (!d.has_type() || d.type() != ::dnstap::Dnstap_Type_MESSAGE || !d.has_message()) {
                _logger->warn("dnstap data is wrong type or has no message, skipping frame of size {}", len_data);
                continue;
            }
            dnstap_signal(d);
        } else if (res == fstrm_res_stop) {
            // Normal end of data stream
            break;
        } else {
            // Abnormal end
            _logger->warn(fmt::format("fstrm_reader_read() data stream ended abnormally: {}", res));
            break;
        }
    }

    // Cleanup
    fstrm_reader_destroy(&r);
}

void DnstapInputStream::start()
{

    if (_running) {
        return;
    }

    if (config_exists("dnstap_file")) {
        // read from dnstap file. this is a special case from a command line utility
        _running = true;
        _read_frame_stream();
        return;
    } else if (config_exists("socket")) {
        // main io loop, run in its own thread
        _io_loop = uvw::Loop::create();
        if (!_io_loop) {
            throw DnstapException("unable to create io loop");
        }
        // AsyncHandle lets us stop the loop from its own thread
        _async_h = _io_loop->resource<uvw::AsyncHandle>();
        _async_h->on<uvw::AsyncEvent>([this](const auto &, auto &hndl) {
            _io_loop->stop();
            _io_loop->close();
            hndl.close();
        });
        // spawn the loop
        _io_thread = std::make_unique<std::thread>([this] {
            _io_loop->run();
        });
    } else {
        throw DnstapException("must specify socket or dnstap_file");
    }

    _running = true;
}

void DnstapInputStream::stop()
{
    if (!_running) {
        return;
    }

    if (_async_h && _io_thread) {
        // we have to use AsyncHandle to stop the loop from the same thread the loop is running in
        _async_h->send();
        // waits for _io_loop->run() to return
        _io_thread->join();
    }

    _running = false;
}

void DnstapInputStream::info_json(json &j) const
{
    common_info_json(j);
}

}
