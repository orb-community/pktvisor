/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DnstapInputStream.h"
#include "dnstap.pb.h"
#include <fstrm/fstrm.h>

namespace visor::input::dnstap {

DnstapInputStream::DnstapInputStream(const std::string &name)
    : visor::InputStream(name)
{
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    _logger = spdlog::get("visor");
    assert(_logger);
    _logger->info("dnstap input created");
}
DnstapInputStream::~DnstapInputStream()
{
    _logger->info("dnstap input destroyed");
}

void DnstapInputStream::_read_frame_stream()
{
    struct fstrm_reader *r = NULL;
    int rv = EXIT_FAILURE;
    fstrm_res res;

    /* Setup file reader options. */
    struct fstrm_file_options *fopt;
    fopt = fstrm_file_options_init();
    assert(config_exists("dnstap_file"));
    fstrm_file_options_set_file_path(fopt, config_get<std::string>("dnstap_file").c_str());

    /* Initialize file reader. */
    r = fstrm_file_reader_init(fopt, NULL);
    if (!r) {
        throw DnstapException("fstrm_file_reader_init() failed");
    }
    res = fstrm_reader_open(r);
    if (res != fstrm_res_success) {
        throw DnstapException("fstrm_reader_open() failed");
    }

    /* Cleanup. */
    fstrm_file_options_destroy(&fopt);

    /* Loop over data frames. */
    for (;;) {
        const uint8_t *data;
        size_t len_data;

        res = fstrm_reader_read(r, &data, &len_data);
        if (res == fstrm_res_success) {
            /* Data frame ready. */
            ::dnstap::Dnstap d;
            if (!d.ParseFromArray(data, len_data)) {
               _logger->warn("ParseFromArray fail");
            }
            _logger->info("frame: {}", d.message().query_message());
        } else if (res == fstrm_res_stop) {
            /* Normal end of data stream. */
            rv = EXIT_SUCCESS;
        } else {
            /* Abnormal end. */
            throw DnstapException(fmt::format("fstrm_reader_read() failed: {}", res));
        }
    }

    /* Cleanup. */
    fstrm_reader_destroy(&r);
}

void DnstapInputStream::start()
{

    if (_running) {
        return;
    }

    _logger->info("dnstap input start()");

    if (config_exists("dnstap_file")) {
        // read from dnstap file. this is a special case from a command line utility
        _dnstapFile = true;
        _running = true;
        _read_frame_stream();
        return;
    }

    _running = true;
}

void DnstapInputStream::stop()
{
    if (!_running) {
        return;
    }

    _logger->info("dnstap input stop()");

    _running = false;
}

void DnstapInputStream::info_json(json &j) const
{
    common_info_json(j);
}

}
