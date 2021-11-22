/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DnstapInputStream.h"
#include <fstrm/fstrm.h>
#include "dnstap.pb.h"

namespace visor::input::dnstap {

DnstapInputStream::DnstapInputStream(const std::string &name)
    : visor::InputStream(name)
{
    _logger = spdlog::get("visor");
    assert(_logger);
    _logger->info("dnstap input created");
}
DnstapInputStream::~DnstapInputStream()
{
    _logger->info("dnstap input destroyed");
}

void DnstapInputStream::start()
{

    if (_running) {
        return;
    }

    _logger->info("dnstap input start()");

    // for unit testing purposes
    if (config_exists("except_on_start")) {
        throw std::runtime_error("dnstap error on start");
    }

    static timer timer_thread{500ms};
    std::srand(std::time(nullptr));
    _dnstap_work = timer_thread.set_interval(1s, [this] {
        _logger->info("dnstap input sends random int signal");
        random_int_signal(std::rand());
    });

    _running = true;
}

void DnstapInputStream::stop()
{
    if (!_running) {
        return;
    }

    _logger->info("dnstap input stop()");

    _dnstap_work->cancel();

    _running = false;
}

void DnstapInputStream::info_json(json &j) const
{
    common_info_json(j);
}

}
