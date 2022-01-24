/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "SflowInputStream.h"

namespace visor::input::sflow {

SflowInputStream::SflowInputStream(const std::string &name)
    : visor::InputStream(name)
{
    _logger = spdlog::get("visor");
    assert(_logger);
    _logger->info("mock input created");
}
SflowInputStream::~SflowInputStream()
{
    _logger->info("mock input destroyed");
}

void SflowInputStream::start()
{

    if (_running) {
        return;
    }

    _logger->info("mock input start()");

    // for unit testing purposes
    if (config_exists("except_on_start")) {
        throw std::runtime_error("mock error on start");
    }

    static timer timer_thread{500ms};
    std::srand(std::time(nullptr));
    _mock_work = timer_thread.set_interval(1s, [this] {
        auto i = std::rand();
        _logger->info("mock input sends random int signal: {}", i);
        random_int_signal(i);
    });

    _running = true;
}

void SflowInputStream::stop()
{
    if (!_running) {
        return;
    }

    _logger->info("mock input stop()");

    _mock_work->cancel();

    _running = false;
}

void SflowInputStream::info_json(json &j) const
{
    common_info_json(j);
}

}
