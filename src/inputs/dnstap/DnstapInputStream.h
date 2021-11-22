/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "InputStream.h"
#include <sigslot/signal.hpp>
#include <spdlog/spdlog.h>

namespace visor::input::dnstap {

class DnstapInputStream : public visor::InputStream
{

    std::shared_ptr<timer::interval_handle> _dnstap_work;
    std::shared_ptr<spdlog::logger> _logger;

public:
    DnstapInputStream(const std::string &name);
    ~DnstapInputStream();

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
        return random_int_signal.slot_count();
    }

    // handler functionality
    // IF THIS changes, see consumer_count()
    // note: these are mutable because consumer_count() calls slot_count() which is not const (unclear if it could/should be)
    mutable sigslot::signal<uint64_t> random_int_signal;
};

}
