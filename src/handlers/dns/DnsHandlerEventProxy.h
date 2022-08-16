/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "StreamHandler.h"
#include "PcapInputStream.h"

namespace visor::handler::dns {

using namespace visor::input::pcap;

class DnsHandlerEventProxy : public visor::HandlerEventProxy
{
public:
    DnsHandlerEventProxy(const std::string &name)
        : HandlerEventProxy(name)
    {
    }

    ~DnsHandlerEventProxy() = default;

    size_t consumer_count() const override
    {
        return heartbeat_signal.slot_count() + udp_signal.slot_count() + start_tstamp_signal.slot_count() + end_tstamp_signal.slot_count();
    }

    mutable sigslot::signal<timespec> start_tstamp_signal;
    mutable sigslot::signal<timespec> end_tstamp_signal;
    mutable sigslot::signal<pcpp::Packet &, PacketDirection, pcpp::ProtocolType, uint32_t, timespec> udp_signal;
};

}