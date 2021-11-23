/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "InputStream.h"
#include <DnsLayer.h>
#include <sigslot/signal.hpp>
#include <spdlog/spdlog.h>

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
    bool _dnstapFile = false;

    std::shared_ptr<spdlog::logger> _logger;

    void _read_frame_stream();

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
        return dnstap_signal.slot_count();
    }

    // handler functionality
    // IF THIS changes, see consumer_count()
    // note: these are mutable because consumer_count() calls slot_count() which is not const (unclear if it could/should be)
    mutable sigslot::signal<pcpp::DnsLayer *> dnstap_signal;
};

}
