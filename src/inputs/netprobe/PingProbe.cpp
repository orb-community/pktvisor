#include "PingProbe.h"

#include "NetProbeException.h"
#include <IcmpLayer.h>
#include <Packet.h>
#include <uvw/dns.h>
#include <uvw/idle.h>

namespace visor::input::netprobe {

sigslot::signal<pcpp::Packet &, timespec> PingReceiver::recv_signal;

PingReceiver::PingReceiver()
{
    _setup_receiver();
}
PingReceiver::~PingReceiver()
{
    _poll->close();
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    closesocket(_sock);
    _sock = INVALID_SOCKET;
#else
    close(_sock);
    _sock = SOCKET_ERROR;
#endif

    if (_async_h && _io_thread) {
        // we have to use AsyncHandle to stop the loop from the same thread the loop is running in
        _async_h->send();
        // waits for _io_loop->run() to return
        if (_io_thread->joinable()) {
            _io_thread->join();
        }
    }
}

void PingReceiver::_setup_receiver()
{
    _io_loop = uvw::Loop::create();
    if (!_io_loop) {
        throw NetProbeException("unable to create io loop");
    }
    // AsyncHandle lets us stop the loop from its own thread
    _async_h = _io_loop->resource<uvw::AsyncHandle>();
    if (!_async_h) {
        throw NetProbeException("unable to initialize AsyncHandle");
    }
    _async_h->once<uvw::AsyncEvent>([this](const auto &, auto &handle) {
        _io_loop->stop();
        _io_loop->close();
        handle.close();
    });

    _sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    if (_sock == INVALID_SOCKET) {
        throw NetProbeException("unable to create receiver socket");
    }
    unsigned long flag = 1;
    if (ioctlsocket(_sock, FIONBIO, &flag) == SOCKET_ERROR) {
        throw NetProbeException("unable to create receiver socket");
    }
#else
    if (_sock == SOCKET_ERROR) {
        _sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    }
    int flag = 1;
    if ((flag = fcntl(_sock, F_GETFL, 0)) == SOCKET_ERROR) {
        throw NetProbeException("unable to create receiver socket");
    }
    if (fcntl(_sock, F_SETFL, flag | O_NONBLOCK) == SOCKET_ERROR) {
        throw NetProbeException("unable to create receiver socket");
    }
#endif

    int opt = 1;
    setsockopt(_sock, SOL_SOCKET, SO_TIMESTAMPNS, &opt, sizeof(opt));

    _poll = _io_loop->resource<uvw::PollHandle>(static_cast<uvw::OSSocketHandle>(_sock));
    if (!_poll) {
        throw NetProbeException("PingProbe - unable to initialize PollHandle");
    }
    _poll->on<uvw::ErrorEvent>([](const auto &, auto &handler) {
        handler.close();
    });

    _poll->on<uvw::PollEvent>([this](const uvw::PollEvent &, auto &) {
        size_t len = sizeof(pcpp::icmphdr) + 256 * 2;
        auto array = std::make_unique<uint8_t[]>(len);
        int rc{0};
        sockaddr_in addr;
        iovec msg_iov{array.get(), len};
        char msg_control[1024];
        msghdr recv_msghdr = {&addr, sizeof(sockaddr_in), &msg_iov, 1, &msg_control, sizeof(msg_control), 0};
        while (rc != SOCKET_ERROR) {
            rc = recvmsg(_sock, &recv_msghdr, MSG_TRUNC);
            if (rc != SOCKET_ERROR) {
                cmsghdr *cmsg{nullptr};
                timespec stamp;
                for (cmsg = CMSG_FIRSTHDR(&recv_msghdr);
                     cmsg != NULL;
                     cmsg = CMSG_NXTHDR(&recv_msghdr, cmsg)) {
                    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPNS) {
                        memcpy(&stamp, CMSG_DATA(cmsg), sizeof(stamp));
                    }
                }
                //std::timespec_get(&stamp, TIME_UTC);
                timeval time;
                TIMESPEC_TO_TIMEVAL(&time, &stamp);
                pcpp::RawPacket raw(array.get(), rc, time, false, pcpp::LINKTYPE_DLT_RAW1);
                pcpp::Packet packet(&raw, pcpp::ICMP);
                recv_signal(packet, stamp);
            }
        }
    });

    _poll->init();
    _poll->start(uvw::PollHandle::Event::READABLE);

    // spawn the loop
    _io_thread = std::make_unique<std::thread>([this] {
        _io_loop->run();
    });
}

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

    // execute once
    static auto receiver = std::make_unique<PingReceiver>();

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

        _get_addr();

        if (auto error = _create_socket(); error.has_value()) {
            _fail(error.value(), TestType::Ping, _name);
            return;
        }

        _internal_timer = _io_loop->resource<uvw::TimerHandle>();
        _internal_timer->on<uvw::TimerEvent>([this](const auto &, auto &) {
            if (_internal_sequence < _packets_per_test) {
                _internal_sequence++;
                _timeout_timer->stop();
                _timeout_timer->start(uvw::TimerHandle::Time{_timeout_msec}, uvw::TimerHandle::Time{0});
                _send_icmp_v4(_internal_sequence);
            }
        });

        _recv_connection = PingReceiver::recv_signal.connect([this](pcpp::Packet &packet, timespec stamp) { _recv(packet, TestType::Ping, _name, stamp); });

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
    _recv_connection.disconnect();
    return true;
}

void PingProbe::_get_addr()
{
    if (_ip_set) {
        return;
    }

    // don't need dns resolution
    if (_dns.empty()) {
        if (_ip.isIPv4()) {
            uint32_t ip_int(_ip.getIPv4().toInt());
            memcpy(&_sa.sin_addr, &ip_int, sizeof(_sa.sin_addr));
            _sa.sin_family = AF_INET;
            _sin_length = sizeof(_sa);
            _ip_set = true;
            return;
        } else {
            _is_ipv6 = true;
            auto ip_bytes = _ip.getIPv6().toBytes();
            for (int i = 0; i < 16; ++i) {
                _sa6.sin6_addr.s6_addr[i] = ip_bytes[i];
            }
            _sa6.sin6_family = AF_INET6;
            _sin_length = sizeof(_sa6);
            _ip_set = true;
        }
    }

    // do Dns lookup for interval loop
    auto request = _io_loop->resource<uvw::GetAddrInfoReq>();
    auto response = request->nodeAddrInfoSync(_dns);
    if (!response.first) {
        return;
    }

    auto addr = response.second.get();
    while (addr->ai_next != nullptr) {
        if (addr->ai_family == AF_INET) {
            memcpy(&_sa, reinterpret_cast<sockaddr_in *>(addr->ai_addr), sizeof(struct sockaddr_in));
            _sin_length = sizeof(_sa);
            _sa.sin_family = AF_INET;
            return;
        } else if (addr->ai_family == AF_INET6) {
            memcpy(&_sa6, reinterpret_cast<sockaddr_in6 *>(addr->ai_addr), sizeof(struct sockaddr_in6));
            _sin_length = sizeof(_sa6);
            _sa6.sin6_family = AF_INET6;
        }
        addr = addr->ai_next;
    }

    return;
}

std::optional<ErrorType> PingProbe::_create_socket()
{
    if (_sock != SOCKET_ERROR) {
        return std::nullopt;
    }

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
    auto rc = sendto(_sock, icmp.getData(), icmp.getDataLen(), 0, reinterpret_cast<sockaddr *>(&_sa), _sin_length);
    if (rc != SOCKET_ERROR) {
        pcpp::Packet packet;
        packet.addLayer(&icmp);
        _send(packet, TestType::Ping, _name, stamp);
    }
}

void PingProbe::_close_socket()
{
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    closesocket(_sock);
    _sock = INVALID_SOCKET;
#else
    close(_sock);
    _sock = SOCKET_ERROR;
#endif
}
}
