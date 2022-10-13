#include "PingProbe.h"

#include "NetProbeException.h"
#include <IcmpLayer.h>
#include <Packet.h>
#include <TimespecTimeval.h>
#include <iostream>
#include <uvw/dns.h>

namespace visor::input::netprobe {

bool PingProbe::start(std::shared_ptr<uvw::Loop> io_loop)
{
    if (_init || (!_ip.isValid() && _dns.empty())) {
        return false;
    }

    // TODO support ICMPv6
    if (_ip.isIPv6()) {
        return false;
    }
    // add validator
    _payload_array = validator;
    if (_packet_payload_size < validator.size()) {
        _packet_payload_size = validator.size();
    }
    _payload_array.resize(_packet_payload_size);
    std::fill(_payload_array.begin() + validator.size(), _payload_array.end(), 0);

    _io_loop = io_loop;

    _interval_timer = _io_loop->resource<uvw::TimerHandle>();
    if (!_interval_timer) {
        throw NetProbeException("PingProbe - unable to initialize interval TimerHandle");
    }
    _interval_timer->on<uvw::TimerEvent>([this](const auto &, auto &) {
        _internal_sequence = 0;

        _timeout_timer = _io_loop->resource<uvw::TimerHandle>();
        if (!_timeout_timer) {
            throw NetProbeException("PingProbe - unable to initialize timeout TimerHandle");
        }

        _timeout_timer->on<uvw::TimerEvent>([this](const auto &, auto &) {
            _internal_sequence = _packets_per_test;
            _fail(ErrorType::Timeout, TestType::Ping, _name);
            _close_socket();
            if (_internal_timer) {
                _internal_timer->stop();
            }
            _interval_timer->again();
        });

        if (auto error = _create_socket(); error.has_value()) {
            _fail(error.value(), TestType::Ping, _name);
            return;
        }

        _poll = _io_loop->resource<uvw::PollHandle>(static_cast<uvw::OSSocketHandle>(_sock));
        if (!_poll) {
            throw NetProbeException("PingProbe - unable to initialize PollHandle");
        }
        _poll->on<uvw::ErrorEvent>([](const auto &, auto &handler) {
            handler.close();
        });
        _internal_timer = _io_loop->resource<uvw::TimerHandle>();
        _internal_timer->on<uvw::TimerEvent>([this](const auto &, auto &) {
            if (_internal_sequence < _packets_per_test) {
                _internal_sequence++;
                _timeout_timer->stop();
                _timeout_timer->start(uvw::TimerHandle::Time{_timeout_msec}, uvw::TimerHandle::Time{0});
                _send_icmp_v4(_internal_sequence);
            }
        });

        if (!_is_ipv6) {
            _poll->on<uvw::PollEvent>([this](const uvw::PollEvent &, auto &) {
                _recv_icmp_v4();
                _timeout_timer->stop();
                if (_internal_sequence >= _packets_per_test) {
                    // received last packet
                    _internal_timer->stop();
                    _close_socket();
                }
            });
        }

        _poll->init();
        _poll->start(uvw::PollHandle::Event::READABLE);

        (_sequence == USHRT_MAX) ? _sequence = 0 : _sequence++;
        _send_icmp_v4(_internal_sequence);
        _internal_sequence++;
        _timeout_timer->start(uvw::TimerHandle::Time{_timeout_msec}, uvw::TimerHandle::Time{0});
        _internal_timer->start(uvw::TimerHandle::Time{_packets_interval_msec}, uvw::TimerHandle::Time{_packets_interval_msec});
    });

    _interval_timer->start(uvw::TimerHandle::Time{0}, uvw::TimerHandle::Time{_interval_msec});
    _init = true;
    return true;
}

bool PingProbe::stop()
{
    _interval_timer->stop();
    return true;
}

sockaddr PingProbe::_get_addr()
{

    sockaddr s_addr;
    sockaddr_in _sa;
    sockaddr_in6 _sa6;
    // don't need dns resolution
    if (_dns.empty()) {
        if (_ip.isIPv4()) {
            uint32_t ip_int(_ip.getIPv4().toInt());
            memcpy(&_sa.sin_addr, &ip_int, sizeof(_sa.sin_addr));
            _sa.sin_family = AF_INET;
            _sin_length = sizeof(_sa);
            memcpy(&s_addr, &_sa, sizeof(_sa));
            return s_addr;
        } else {
            _is_ipv6 = true;
            auto ip_bytes = _ip.getIPv6().toBytes();
            for (int i = 0; i < 16; ++i) {
                _sa6.sin6_addr.s6_addr[i] = ip_bytes[i];
            }
            _sa6.sin6_family = AF_INET6;
            _sin_length = sizeof(_sa6);
            memcpy(&s_addr, &_sa6, sizeof(_sa6));
            return s_addr;
        }
    }

    // do Dns lookup for interval loop
    auto request = _io_loop->resource<uvw::GetAddrInfoReq>();
    auto response = request->nodeAddrInfoSync(_dns);
    if (!response.first) {
        return s_addr;
    }

    auto addr = response.second.get();
    while (addr->ai_next != nullptr) {
        if (addr->ai_family == AF_INET) {
            memcpy(&_sa, reinterpret_cast<sockaddr_in *>(addr->ai_addr), sizeof(struct sockaddr_in));
            _sin_length = sizeof(_sa);
            _sa.sin_family = AF_INET;
            memcpy(&s_addr, &_sa, sizeof(_sa));
            return s_addr;
        } else if (addr->ai_family == AF_INET6) {
            memcpy(&_sa6, reinterpret_cast<sockaddr_in6 *>(addr->ai_addr), sizeof(struct sockaddr_in6));
            _sin_length = sizeof(_sa6);
            _sa6.sin6_family = AF_INET6;
        }
        addr = addr->ai_next;
    }

    return s_addr;
}

std::optional<ErrorType> PingProbe::_create_socket()
{
    int domain = AF_INET;
    if (_is_ipv6) {
        domain = AF_INET6;
    }

    _sock = socket(domain, SOCK_RAW, IPPROTO_ICMP);
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    if (_sock == INVALID_SOCKET) {
        return ErrorType::SocketError;
    }
    unsigned long flag = 1;
    if (ioctlsocket(_sock, FIONBIO, &flag) == SOCKET_ERROR) {
        return ErrorType::SocketError;
    }
#else
    if (_sock == SOCKET_ERROR) {
        _sock = socket(domain, SOCK_DGRAM, IPPROTO_ICMP);
    }
    int flag = 1;
    if ((flag = fcntl(_sock, F_GETFL, 0)) == SOCKET_ERROR) {
        return ErrorType::SocketError;
    }
    if (fcntl(_sock, F_SETFL, flag | O_NONBLOCK) == SOCKET_ERROR) {
        return ErrorType::SocketError;
    }
#endif
    return std::nullopt;
}

void PingProbe::_send_icmp_v4(uint16_t sequence)
{
    auto icmp = pcpp::IcmpLayer();
    timespec stamp;
    std::timespec_get(&stamp, TIME_UTC);
    const uint64_t stamp64 = stamp.tv_sec * 1000000000ULL + stamp.tv_nsec;
    icmp.setEchoRequestData(static_cast<uint16_t>(_id * _sequence), sequence, stamp64, _payload_array.data(), _payload_array.size());
    icmp.computeCalculateFields();
    auto addr = _get_addr();
    auto rc = sendto(_sock, icmp.getData(), icmp.getDataLen(), 0, &addr, _sin_length);
    if (rc != SOCKET_ERROR) {
        pcpp::Packet packet;
        packet.addLayer(&icmp);
        _send(packet, TestType::Ping, _name, stamp);
    }
}

void PingProbe::_recv_icmp_v4()
{
    size_t len = sizeof(pcpp::icmphdr) + _packet_payload_size * 2;
    auto array = std::make_unique<uint8_t[]>(len);
    auto addr = _get_addr();
    auto rc = recvfrom(_sock, array.get(), len, 0, &addr, &_sin_length);
    if (rc != SOCKET_ERROR) {
        timespec stamp;
        std::timespec_get(&stamp, TIME_UTC);
        timeval time;
        TIMESPEC_TO_TIMEVAL(&time, &stamp);
        pcpp::RawPacket raw(array.get(), rc, time, false, pcpp::LINKTYPE_DLT_RAW1);
        pcpp::Packet packet(&raw, pcpp::ICMP);
        _recv(packet, TestType::Ping, _name, stamp);
    }
}

void PingProbe::_close_socket()
{
    _poll->close();
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    closesocket(_sock);
    _sock = INVALID_SOCKET;
#else
    close(_sock);
    _sock = SOCKET_ERROR;
#endif
}
}
