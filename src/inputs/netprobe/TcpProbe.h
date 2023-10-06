/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "NetProbe.h"

#include <uvw/tcp.h>
#include <uvw/timer.h>

namespace visor::input::netprobe {

class TcpProbe final : public NetProbe
{
    uint32_t _dst_port;
    bool _init{false};
    bool _is_ipv4{false};
    std::string _ip_str;
    std::shared_ptr<uvw::TimerHandle> _interval_timer;

    std::shared_ptr<uvw::TCPHandle> _client;

    void _perform_tcp_process();

public:
    TcpProbe(uint16_t id, const std::string &name, const pcpp::IPAddress &ip, const std::string &dns, uint32_t port)
        : NetProbe(id, name, ip, dns)
        , _dst_port(port) {};
    ~TcpProbe() = default;
    bool start(std::shared_ptr<uvw::Loop> io_loop) override;
    bool stop() override;
};
}
