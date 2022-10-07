/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "NetProbeInputStream.h"
#include "NetProbeException.h"
#include "PingProbe.h"
#include "ThreadName.h"
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <UdpLayer.h>

namespace visor::input::netprobe {

NetProbeInputStream::NetProbeInputStream(const std::string &name)
    : visor::InputStream(name)
{
    _logger = spdlog::get("visor");
    assert(_logger);
}

void NetProbeInputStream::start()
{
    if (_running) {
        return;
    }

    std::vector<std::string> valid_tests;
    for (const auto &defs : _test_defs) {
        valid_tests.push_back(defs.first);
    }

    // Configs
    if (!config_exists("test_type")) {
        throw NetProbeException(fmt::format("Test type not specified. The valid test types are: {}", fmt::join(valid_tests, ", ")));
    } else {
        auto it = _test_defs.find(config_get<std::string>("test_type"));
        if (it == _test_defs.end()) {
            throw NetProbeException(fmt::format("{} is an invalid/unsupported test type. The valid test types are: {}", config_get<std::string>("test_type"), fmt::join(valid_tests, ", ")));
        }
        _type = it->second;
    }

    if (config_exists("interval_msec")) {
        _interval_msec = config_get<uint64_t>("interval_msec");
    }

    if (config_exists("timeout_msec")) {
        _timeout_msec = config_get<uint64_t>("timeout_msec");
    }

    if (config_exists("packets_per_test")) {
        _packets_per_test = config_get<uint64_t>("packets_per_test");
    }

    if (config_exists("packets_interval_msec")) {
        _packets_interval_msec = config_get<uint64_t>("packets_interval_msec");
    }

    if (config_exists("packet_payload_size")) {
        _packet_payload_size = config_get<uint64_t>("packet_payload_size");
    }

    if (!config_exists("targets")) {
        throw NetProbeException("no targets specified");
    } else {
        auto targets_list = config_get<StringList>("targets");
        for (const auto &target : targets_list) {
            auto ip = pcpp::IPAddress(target);
            if (ip.isValid()) {
                _ip_list.push_back(ip);
                continue;
            }
            auto dot = target.find(".");
            if (dot == std::string::npos) {
                throw NetProbeException(fmt::format("{} is an invalid/unsupported DNS", target));
            }
            _dns_list.push_back(target);
        }
    }

    _create_netprobe_loop();

    _running = true;
}

void NetProbeInputStream::_create_netprobe_loop()
{
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

    for (const auto &ip : _ip_list) {
        if (_type == TestType::Ping) {
            auto ping = std::make_unique<PingProbe>();
            ping->set_configs(_interval_msec, _timeout_msec, _packets_per_test, _packets_interval_msec, _packet_payload_size);
            ping->set_target(ip, std::string());
            ping->start(_io_loop);
            _probes.push_back(std::move(ping));
        }
    }

    for (const auto &dns : _dns_list) {
        if (_type == TestType::Ping) {
            auto ping = std::make_unique<PingProbe>();
            ping->set_configs(_interval_msec, _timeout_msec, _packets_per_test, _packets_interval_msec, _packet_payload_size);
            ping->set_target(pcpp::IPAddress(), dns);
            ping->set_callbacks([this](pcpp::Packet &payload, TestType type, const std::string &name) {
                std::shared_lock lock(_input_mutex);
                for (auto &proxy : _event_proxies) {
                    static_cast<NetProbeInputEventProxy *>(proxy.get())->probe_recv_cb(payload, type, name);
                } },
                [this](pcpp::Packet &payload, TestType type, const std::string &name) {
                    std::shared_lock lock(_input_mutex);
                    for (auto &proxy : _event_proxies) {
                        static_cast<NetProbeInputEventProxy *>(proxy.get())->probe_fail_cb(payload, type, name);
                    } });
            ping->start(_io_loop);
            _probes.push_back(std::move(ping));
        }
    }

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

    for (const auto &probe : _probes) {
        probe->stop();
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
}

std::unique_ptr<InputEventProxy> NetProbeInputStream::create_event_proxy(const Configurable &filter)
{
    return std::make_unique<NetProbeInputEventProxy>(_name, filter);
}
}
