/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "NetProbeInputStream.h"
#include "NetProbeException.h"
#include "ThreadName.h"
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <UdpLayer.h>

namespace visor::input::netprobe {

NetProbeInputStream::NetProbeInputStream(const std::string &name)
    : visor::InputStream(name)
    , _error_count(0)
{
    _logger = spdlog::get("visor");
    assert(_logger);
}

void NetProbeInputStream::start()
{
    if (_running) {
        return;
    }

    // main io loop, run in its own thread
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
        _timer->stop();
        _timer->close();
        _io_loop->stop();
        _io_loop->close();
        handle.close();
    });
    _async_h->on<uvw::ErrorEvent>([this](const auto &err, auto &handle) {
        _logger->error("[{}] AsyncEvent error: {}", _name, err.what());
        handle.close();
    });

    _timer = _io_loop->resource<uvw::TimerHandle>();
    if (!_timer) {
        throw NetProbeException("unable to initialize TimerHandle");
    }
    _timer->on<uvw::TimerEvent>([this](const auto &, auto &) {
        timespec stamp;
        // use now()
        std::timespec_get(&stamp, TIME_UTC);
        std::shared_lock lock(_input_mutex);
        for (auto &proxy : _event_proxies) {
            proxy->heartbeat_cb(stamp);
        }
    });
    _timer->on<uvw::ErrorEvent>([this](const auto &err, auto &handle) {
        _logger->error("[{}] TimerEvent error: {}", _name, err.what());
        handle.close();
    });

    // setup server socket
    _icmp = std::make_unique<network::ICMPSocket>();
    pcpp::IPAddress ip("8.8.8.8");
    _icmp->create(ip, _io_loop);

    _running = true;

    // spawn the loop
    _io_thread = std::make_unique<std::thread>([this] {
        _timer->start(uvw::TimerHandle::Time{1000}, uvw::TimerHandle::Time{HEARTBEAT_INTERVAL * 1000});
        thread::change_self_name(schema_key(), name());
        _io_loop->run();
    });
}

void NetProbeInputStream::stop()
{
    if (!_running) {
        return;
    }

    if (_async_h && _io_thread) {
        // we have to use AsyncHandle to stop the loop from the same thread the loop is running in
        _async_h->send();
        // waits for _io_loop->run() to return
        if (_io_thread->joinable()) {
            _io_thread->join();
        }
    }

    _running = false;
}

void NetProbeInputStream::info_json(json &j) const
{
    common_info_json(j);
    j[schema_key()]["packet_errors"] = _error_count.load();
}

std::unique_ptr<InputEventProxy> NetProbeInputStream::create_event_proxy(const Configurable &filter)
{
    return std::make_unique<NetProbeInputEventProxy>(_name, filter);
}
}
