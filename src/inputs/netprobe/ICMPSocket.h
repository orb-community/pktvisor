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
#define SOCKET_ERROR -1
typedef socklen_t SOCKETLEN;
typedef int SOCKET;
#endif
#include <IpAddress.h>
#include <memory>
#include <uvw/poll.h>

namespace visor::network {
class ICMPSocket
{
    SOCKET _sock{0};
    bool _init{false};
    std::shared_ptr<uvw::PollHandle> _poll;
    struct sockaddr_in _sa;
    struct sockaddr_in6 _sa6;
    SOCKETLEN _sin_length{0};

public:
    ICMPSocket(){};
    ~ICMPSocket() = default;

    bool create(const pcpp::IPAddress &ip, std::shared_ptr<uvw::Loop> io_loop);
    bool send(const pcpp::IPAddress &ip);
};
}
