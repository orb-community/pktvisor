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
#define INVALID_SOCKET -1
typedef socklen_t SOCKETLEN;
typedef int SOCKET;
#endif
#include "NetProbe.h"
#include <IcmpLayer.h>
#include <IpAddress.h>
#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <sigslot/signal.hpp>
#include <uvw/async.h>
#include <uvw/poll.h>
#include <uvw/timer.h>

namespace visor::input::netprobe {

/**
 * @class PingReceiver
 * @brief PingReceiver class used for receiving ICMP Echo Responses.
 *
 *  This class is statically created, It means that it will be a single PingReceiver per Pktvisor process.
 */
class PingReceiver
{
    std::array<char, sizeof(pcpp::icmphdr) + 65507> _array;
    SOCKET _sock{INVALID_SOCKET};
    std::shared_ptr<uvw::PollHandle> _poll;
    std::unique_ptr<std::thread> _io_thread;
    std::shared_ptr<uvw::Loop> _io_loop;
    std::shared_ptr<uvw::AsyncHandle> _async_h;

    void _setup_receiver();

public:
    static sigslot::signal<pcpp::Packet &, timespec> recv_signal;

    PingReceiver();
    ~PingReceiver();
};

/**
 * @class PingProbe
 * @brief PingProbe class used for sending ICMP Echo Requests.
 *
 *  This class is created for each specified target. However, it reuses a shared socket per thread (per UV_LOOP).
 *  I.e. each unique NetProbeInputStream with Ping Type will have a socket to send ICMP Echo Request.
 */
class PingProbe final : public NetProbe
{
    static thread_local SOCKET _sock;

    bool _init{false};
    bool _is_ipv6{false};
    bool _ip_set{false};
    uint16_t _sequence{0};
    uint16_t _internal_sequence{0};
    std::shared_ptr<uvw::TimerHandle> _interval_timer;
    std::shared_ptr<uvw::TimerHandle> _internal_timer;
    std::shared_ptr<uvw::TimerHandle> _timeout_timer;
    SOCKETLEN _sin_length{0};
    std::vector<uint8_t> _payload_array;
    sockaddr_in _sa;
    sockaddr_in6 _sa6;
    sigslot::connection _recv_connection;

    void _get_addr();
    void _send_icmp_v4(uint16_t sequence);
    std::optional<ErrorType> _create_socket();
    void _close_socket();

public:
    static thread_local std::atomic<uint32_t> sock_count;

    PingProbe(uint16_t id, const std::string &name)
        : NetProbe(id, name){};
    ~PingProbe() = default;
    bool start(std::shared_ptr<uvw::Loop> io_loop) override;
    bool stop() override;
};
}
