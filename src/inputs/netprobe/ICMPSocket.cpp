#include "ICMPSocket.h"

#include <IcmpLayer.h>
#include <Packet.h>
#include <iostream>
#include <uvw/loop.h>
#include <uvw/stream.h>

namespace visor::network {

bool ICMPSocket::create(const pcpp::IPAddress &ip, std::shared_ptr<uvw::Loop> io_loop)
{
    if (_init || !ip.isValid()) {
        return false;
    }

    int domain = AF_INET;
    if (ip.isIPv4()) {
        memset(&_sa, 0, sizeof(struct sockaddr_in));
        uint32_t ip_int(ip.getIPv4().toInt());
        memcpy(&_sa.sin_addr, &ip_int, sizeof(_sa.sin_addr));
        _sa.sin_family = AF_INET;
        _sin_length = sizeof(_sa);
    } else {
        domain = AF_INET6;
        memset(&_sa6, 0, sizeof(struct sockaddr_in6));
        auto ip_bytes = ip.getIPv6().toBytes();
        for (int i = 0; i < 16; ++i) {
            _sa6.sin6_addr.s6_addr[i] = ip_bytes[i];
        }
        _sa6.sin6_family = AF_INET6;
        _sin_length = sizeof(_sa6);
    }

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    _sock = socket(domain, SOCK_RAW, IPPROTO_ICMP);
    if (_sock == INVALID_SOCKET) {
        return false;
    }
    unsigned long flag = 1;
    if (ioctlsocket(_sock, FIONBIO, &flag) == SOCKET_ERROR) {
        return false;
    }
#else
    _sock = socket(domain, SOCK_DGRAM, IPPROTO_ICMP);
    int flag = 1;
    if ((flag = fcntl(_sock, F_GETFL, 0)) == SOCKET_ERROR) {
        return false;
    }
    if (fcntl(_sock, F_SETFL, flag | O_NONBLOCK) == SOCKET_ERROR) {
        return false;
    }
#endif

    _poll = io_loop->resource<uvw::PollHandle>(static_cast<uvw::OSSocketHandle>(_sock));
    if (!_poll) {
        return false;
    }

    _poll->on<uvw::ErrorEvent>([](const auto &, auto &handler) {
        handler.close();
    });

    if (ip.isIPv4()) {
        _poll->on<uvw::PollEvent>([this](const uvw::PollEvent &event, auto &) {
            if (event.flags & uvw::details::UVPollEvent::READABLE) {
                std::unique_ptr<uint8_t[]> array(new uint8_t[256]);
                auto rc = recvfrom(_sock, array.get(), 256, 0, reinterpret_cast<struct sockaddr *>(&_sa), &_sin_length);
                pcpp::Packet dummy_packet;
                auto icmp = pcpp::IcmpLayer(array.get(), rc, nullptr, &dummy_packet);
                std::cerr << icmp.getMessageType() << '\n';
            }
        });
    } else {
    }

    _poll->init();
    _poll->start(uvw::PollHandle::Event::READABLE);

    if (ip.isIPv4()) {
        auto icmp = pcpp::IcmpLayer();
        timespec stamp;
        std::timespec_get(&stamp, TIME_UTC);
        std::unique_ptr<uint8_t[]> array(new uint8_t[48]);
        icmp.setEchoRequestData(0x624, static_cast<uint16_t>(stamp.tv_nsec), static_cast<uint64_t>(stamp.tv_sec), array.get(), 48);
        icmp.computeCalculateFields();
        sendto(_sock, icmp.getData(), icmp.getDataLen(), 0, reinterpret_cast<struct sockaddr *>(&_sa), _sin_length);
    } else {
        // sendto(_sock, data, length, 0, (struct sockaddr *)&sa, sizeof(sa));
    }

    return true;
}

bool ICMPSocket::send([[maybe_unused]] const pcpp::IPAddress &ip)
{
    return false;
}
}
