#include "TcpProbe.h"

#include "NetProbeException.h"
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include <VisorTcpLayer.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

namespace visor::input::netprobe {
bool TcpProbe::start(std::shared_ptr<uvw::Loop> io_loop)
{
    if (_init || (!_ip.isValid() && _dns.empty())) {
        return false;
    }

    if (_dns.empty()) {
        _ip_str = _ip.toString();
        _is_ipv4 = _ip.isIPv4();
    }

    _io_loop = io_loop;
    _interval_timer = _io_loop->resource<uvw::TimerHandle>();
    if (!_interval_timer) {
        throw NetProbeException("Netprobe - unable to initialize interval TimerHandle");
    }

    _interval_timer->on<uvw::TimerEvent>([this](const auto &, auto &) {

        if (!_dns.empty()) {
            auto [ip, ipv4] = _resolve_dns();
            _ip_str = ip;
            _is_ipv4 = ipv4;
            if (_ip_str.empty()) {
                _fail(ErrorType::DnsLookupFailure, TestType::TCP, _name);
                return;
            }
        }
        _perform_tcp_process();
    });

    _interval_timer->start(uvw::TimerHandle::Time{0}, uvw::TimerHandle::Time{_config.interval_msec});
    _init = true;
    return true;
}

void TcpProbe::_perform_tcp_process()
{
    _client = _io_loop->resource<uvw::TCPHandle>();
    _client->on<uvw::ErrorEvent>([this](const auto &, auto &) {
        _fail(ErrorType::ConnectFailure, TestType::TCP, _name);
    });
    _client->once<uvw::CloseEvent>([this](const uvw::CloseEvent &, uvw::TCPHandle &) {
    });
    _client->once<uvw::ShutdownEvent>([this](const uvw::ShutdownEvent &, uvw::TCPHandle &handle) {
        handle.close();
    });
    _client->once<uvw::ConnectEvent>([this](const uvw::ConnectEvent &, uvw::TCPHandle &handle) {
        timespec stamp;
        std::timespec_get(&stamp, TIME_UTC);
        pcpp::Packet packet;
        auto layer = pcpp::TcpLayer(0, static_cast<uint16_t>(_dst_port));
        packet.addLayer(&layer);
        _recv(packet, TestType::TCP, _name, stamp);
        handle.shutdown();
    });
    timespec stamp;
    std::timespec_get(&stamp, TIME_UTC);
    pcpp::Packet packet;
    auto layer = pcpp::TcpLayer(0, static_cast<uint16_t>(_dst_port));
    packet.addLayer(&layer);
    _send(packet, TestType::TCP, _name, stamp);
    if (_is_ipv4) {
        _client->connect<uvw::TCPHandle::IPv4>(_ip_str, _dst_port);
    } else {
        _client->connect<uvw::TCPHandle::IPv6>(_ip_str, _dst_port);
    }
}

bool TcpProbe::stop()
{
    if (_interval_timer) {
        _interval_timer->stop();
    }
    return true;
}
}
