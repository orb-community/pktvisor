/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef _WIN32
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
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#pragma clang diagnostic ignored "-Wc99-extensions"
#endif
#include <IcmpLayer.h>
#include <IpAddress.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <sigslot/signal.hpp>
#include <uvw/async.h>
#include <uvw/check.h>
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
    std::vector<std::shared_ptr<uvw::AsyncHandle>> _callbacks;
    std::shared_ptr<uvw::TimerHandle> _timer;
    std::vector<std::pair<pcpp::Packet, timespec>> _recv_packets;
    void _setup_receiver();

public:
    static std::vector<std::pair<pcpp::Packet, timespec>> recv_packets;

    PingReceiver();
    ~PingReceiver();

    void register_async_callback(std::shared_ptr<uvw::AsyncHandle> callback)
    {
        _callbacks.push_back(callback);
    }

    void remove_async_callback(std::shared_ptr<uvw::AsyncHandle> callback)
    {
        _callbacks.erase(std::remove(_callbacks.begin(), _callbacks.end(), callback), _callbacks.end());
    }
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
    static std::unique_ptr<PingReceiver> _receiver;
    static thread_local SOCKET _sock;

    bool _init{false};
    bool _is_ipv6{false};
    bool _ip_set{false};
    uint8_t _sequence{0};
    uint8_t _internal_sequence{0};
    std::shared_ptr<uvw::TimerHandle> _interval_timer;
    std::shared_ptr<uvw::TimerHandle> _internal_timer;
    std::shared_ptr<uvw::TimerHandle> _timeout_timer;
    std::shared_ptr<uvw::AsyncHandle> _recv_handler;
    SOCKETLEN _sin_length{0};
    std::vector<uint8_t> _payload_array;
    sockaddr_in _sa;
    sockaddr_in6 _sa6;
    uint8_t _bucket{0};

    void _send_icmp_v4(uint8_t sequence);
    std::optional<ErrorType> _get_addr();
    std::optional<ErrorType> _create_socket();
    void _close_socket();

public:
    static thread_local std::atomic<uint32_t> sock_count;

    PingProbe(uint16_t id, const std::string &name, const pcpp::IPAddress &ip, const std::string &dns)
        : NetProbe(id, name, ip, dns){};
    ~PingProbe() = default;
    bool start(std::shared_ptr<uvw::Loop> io_loop) override;
    bool stop() override;
};
}
