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
        _internal_sequence = 0;
        _timeout_timer = _io_loop->resource<uvw::TimerHandle>();
        if (!_timeout_timer) {
            throw NetProbeException("Netprobe - unable to initialize timeout TimerHandle");
        }

        _timeout_timer->on<uvw::TimerEvent>([this](const auto &, auto &) {
            _internal_sequence = _config.packets_per_test;
            _fail(ErrorType::Timeout, TestType::Ping, _name);
            if (_internal_timer) {
                _internal_timer->stop();
            }
            _interval_timer->again();
        });

        if (!_dns.empty()) {
            auto [ip, ipv4] = _resolve_dns();
            _ip_str = ip;
            _is_ipv4 = ipv4;
            if (_ip_str.empty()) {
                _fail(ErrorType::DnsLookupFailure, TestType::Ping, _name);
                return;
            }
        }

        _internal_timer = _io_loop->resource<uvw::TimerHandle>();
        _internal_timer->on<uvw::TimerEvent>([this](const auto &, auto &) {
            if (_internal_sequence < _config.packets_per_test) {
                _internal_sequence++;
                _timeout_timer->stop();
                _timeout_timer->start(uvw::TimerHandle::Time{_config.timeout_msec}, uvw::TimerHandle::Time{0});
                _perform_tcp_process();
            }
        });
        _timeout_timer->start(uvw::TimerHandle::Time{_config.timeout_msec}, uvw::TimerHandle::Time{0});
        _perform_tcp_process();
        _internal_sequence++;
        _internal_timer->start(uvw::TimerHandle::Time{_config.packets_interval_msec}, uvw::TimerHandle::Time{_config.packets_interval_msec});
    });

    _interval_timer->start(uvw::TimerHandle::Time{0}, uvw::TimerHandle::Time{_config.interval_msec});
    _init = true;
    return true;
}

void TcpProbe::_perform_tcp_process()
{
    _client = _io_loop->resource<uvw::TCPHandle>();
    _client->on<uvw::ErrorEvent>([this](const auto &, auto &) {
        _fail(ErrorType::ConnectionFailure, TestType::Ping, _name);
    });
    _client->once<uvw::CloseEvent>([this](const uvw::CloseEvent &, uvw::TCPHandle &) {
        timespec stamp;
        std::timespec_get(&stamp, TIME_UTC);
        pcpp::Packet packet;
        auto layer = pcpp::TcpLayer(static_cast<uint16_t>(_port), _client_port);
        packet.addLayer(&layer);
        _recv(packet, TestType::TCP, _name, stamp);
    });
    _client->once<uvw::ShutdownEvent>([](const uvw::ShutdownEvent &, uvw::TCPHandle &handle) {
        handle.close();
    });
    _client->once<uvw::ConnectEvent>([this](const uvw::ConnectEvent &, uvw::TCPHandle &handle) {
        timespec stamp;
        std::timespec_get(&stamp, TIME_UTC);
        _client_port = static_cast<uint16_t>(handle.sock().port);
        pcpp::Packet packet;
        auto layer = pcpp::TcpLayer(_client_port, static_cast<uint16_t>(_port));
        packet.addLayer(&layer);
        _send(packet, TestType::TCP, _name, stamp);
        handle.shutdown();
    });
    if (_is_ipv4) {
        _client->connect<uvw::TCPHandle::IPv4>(_ip_str, _port);
    } else {
        _client->connect<uvw::TCPHandle::IPv6>(_ip_str, _port);
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
