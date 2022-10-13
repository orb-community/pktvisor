/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#include <Ws2tcpip.h>
#include <winsock2.h>
typedef int SOCKETLEN;
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define SOCKET_ERROR -1
typedef socklen_t SOCKETLEN;
typedef int SOCKET;
#endif
#include "NetProbe.h"
#include <IpAddress.h>
#include <memory>
#include <optional>
#include <uvw/poll.h>
#include <uvw/timer.h>

namespace visor::input::netprobe {

class PingProbe final : public NetProbe
{
    SOCKET _sock{0};
    bool _init{false};
    bool _is_ipv6{false};
    bool _ip_set{false};
    uint16_t _sequence{0};
    uint16_t _internal_sequence{0};
    std::shared_ptr<uvw::PollHandle> _poll;
    std::shared_ptr<uvw::TimerHandle> _interval_timer;
    std::shared_ptr<uvw::TimerHandle> _internal_timer;
    std::shared_ptr<uvw::TimerHandle> _timeout_timer;
    struct sockaddr_in _sa;
    struct sockaddr_in6 _sa6;
    SOCKETLEN _sin_length{0};
    std::vector<uint8_t> _payload_array;

    bool _set_ip();
    void _send_icmp_v4(uint16_t sequence);
    void _recv_icmp_v4();
    std::optional<ErrorType> _create_socket();
    void _close_socket();

public:
    PingProbe(uint16_t id)
        : NetProbe(id){};
    ~PingProbe() = default;

    bool start(std::shared_ptr<uvw::Loop> io_loop) override;
    bool stop() override;
};
}
