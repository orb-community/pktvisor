/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "NetProbeInputStream.h"
#include "DohProbe.h"
#include "HttpClient.h"
#include "HttpProbe.h"
#include "NetProbeException.h"
#include "PingProbe.h"
#include "TcpProbe.h"
#include "ThreadName.h"
#include "dns.h"
#include "visor_config.h"
#include <cctype>
#include <filesystem>
#include <fmt/ranges.h>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/UdpLayer.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

namespace visor::input::netprobe {

namespace {

std::string test_type_name(TestType t)
{
    switch (t) {
    case TestType::Ping:
        return "ping";
    case TestType::HTTP:
        return "http";
    case TestType::UDP:
        return "udp";
    case TestType::TCP:
        return "tcp";
    case TestType::DOH:
        return "doh";
    }
    return "unknown";
}

// Join a per-target "headers" sub-Configurable entry into its "name: value" string. The YAML
// loader stores scalars typed (uint64_t/bool/string), so a header value like `12345` or `true`
// is NOT a std::string in the Configurable and config_get<std::string>() throws on it. Configurable
// exposes no cheaper type-dispatch accessor, so fall back through the scalar types it can hold.
std::string header_value_to_string(const visor::Configurable &headers, const std::string &name)
{
    try {
        return headers.config_get<std::string>(name);
    } catch (const visor::ConfigException &) {
    }
    try {
        return std::to_string(headers.config_get<uint64_t>(name));
    } catch (const visor::ConfigException &) {
    }
    try {
        return headers.config_get<bool>(name) ? "true" : "false";
    } catch (const visor::ConfigException &) {
    }
    throw NetProbeException(fmt::format("netprobe: header '{}' has an unsupported value type", name));
}

// Trim leading/trailing ASCII whitespace.
std::string trim(const std::string &s)
{
    auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    auto last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

}

uint16_t NetProbeInputStream::_id = 1;

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

    validate_configs(_config_defs);

    std::vector<std::string> valid_tests;
    for (const auto &defs : _test_defs) {
        valid_tests.push_back(defs.first);
    }

    // Configs
    if (!config_exists("test_type")) {
        throw NetProbeException(fmt::format("'test_type' config not specified. The valid test types are: {}", fmt::join(valid_tests, ", ")));
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

    if (_timeout_msec > _interval_msec) {
        throw NetProbeException(fmt::format("timeout_msec [{}] cannot be greater than interval_msec [{}]", _timeout_msec, _interval_msec));
    }

    if (config_exists("packets_per_test")) {
        _packets_per_test = config_get<uint64_t>("packets_per_test");
        if (!_packets_per_test) {
            throw NetProbeException("packets_per_test needs to be greater than 0");
        }
    }

    if (config_exists("packets_interval_msec")) {
        _packets_interval_msec = config_get<uint64_t>("packets_interval_msec");
    }

    if (_packets_per_test * _packets_interval_msec > _interval_msec) {
        throw NetProbeException(fmt::format("packets_per_test [{}] times packets_interval_msec [{}] cannot be greater than packets_interval_msec [{}]", _packets_per_test, _packets_interval_msec, _interval_msec));
    }

    if (config_exists("packet_payload_size")) {
        _packet_payload_size = config_get<uint64_t>("packet_payload_size");
        if (_packet_payload_size > MAX_PAYLOAD_SIZE) {
            throw NetProbeException(fmt::format("packet_payload_size was set to {} but max supported size is {}", _packet_payload_size, MAX_PAYLOAD_SIZE));
        }
    }

    if (config_exists("http_method")) {
        _http_method = config_get<std::string>("http_method");
    }

    if (config_exists("qname")) {
        _doh_qname = config_get<std::string>("qname");
        // Normalize a trailing dot (FQDN form, e.g. "example.com."): pcpp encodes/decodes names
        // without it, so keeping it would both corrupt the query wire and break the response
        // question-echo comparison in DohProbe. Guard size>1 so the root "." isn't emptied.
        if (_doh_qname.size() > 1 && _doh_qname.back() == '.') {
            _doh_qname.pop_back();
        }
    }
    if (config_exists("qtype")) {
        _doh_qtype = config_get<std::string>("qtype");
        // Normalize to uppercase before validation/lookup: QTypeNumbers is keyed by uppercase
        // names (e.g. "AAAA"), and the DNS handler uppercases qtype inputs too — so "aaaa"
        // should be accepted, consistent with the rest of the codebase.
        for (auto &ch : _doh_qtype) {
            if (ch >= 'a' && ch <= 'z') {
                ch = static_cast<char>(ch - 'a' + 'A');
            }
        }
    }
    // DoH method defaults to POST; reuse the http_method key if set. (Only meaningful for DoH streams.)
    if (_type == TestType::DOH) {
        _doh_method = config_exists("http_method") ? config_get<std::string>("http_method") : "POST";
        if (_doh_method != "GET" && _doh_method != "POST") {
            throw NetProbeException(fmt::format("unsupported http_method '{}' for doh (use GET or POST)", _doh_method));
        }
    }

    // ---- v2: checks (http only) ----
    if (config_exists("expected_status")) {
        try {
            _http_opts.expected_status = visor::http::StatusMatcher::parse(config_get<StringList>("expected_status"));
        } catch (const std::invalid_argument &e) {
            throw NetProbeException(fmt::format("netprobe: expected_status: {}", e.what()));
        }
    }
    if (config_exists("failure_status")) {
        try {
            _http_opts.failure_status = visor::http::StatusMatcher::parse(config_get<StringList>("failure_status"));
        } catch (const std::invalid_argument &e) {
            throw NetProbeException(fmt::format("netprobe: failure_status: {}", e.what()));
        }
    }
    {
        std::string sub = config_exists("expected_body") ? config_get<std::string>("expected_body") : "";
        std::string rx = config_exists("expected_body_regex") ? config_get<std::string>("expected_body_regex") : "";
        try {
            _http_opts.body_check = visor::http::BodyCheck::compile(sub, rx);
        } catch (const std::invalid_argument &e) {
            throw NetProbeException(fmt::format("netprobe: {}", e.what()));
        }
    }
    if (config_exists("body")) {
        _http_opts.request_body = config_get<std::string>("body");
    }
    if (config_exists("proxy")) {
        _http_opts.proxy = config_get<std::string>("proxy");
    }
    if (config_exists("tls")) {
        auto tls = config_get<std::shared_ptr<Configurable>>("tls");
        if (tls->config_exists("verify")) {
            _http_opts.tls_verify = tls->config_get<bool>("verify");
        }
        if (tls->config_exists("ca_file")) {
            _http_opts.ca_file = tls->config_get<std::string>("ca_file");
        }
        if (tls->config_exists("cert_file")) {
            _http_opts.cert_file = tls->config_get<std::string>("cert_file");
        }
        if (tls->config_exists("key_file")) {
            _http_opts.key_file = tls->config_get<std::string>("key_file");
        }
    }
    _http_opts.user_agent = std::string("pktvisor/") + VISOR_VERSION_NUM;

    if (!config_exists("targets")) {
        throw NetProbeException("no targets specified");
    } else {
        auto targets = config_get<std::shared_ptr<Configurable>>("targets");
        auto keys = targets->get_all_keys();
        for (const auto &key : keys) {
            auto config = targets->config_get<std::shared_ptr<Configurable>>(key);
            if (!config->config_exists("target")) {
                throw NetProbeException(fmt::format("'{}' does not have key 'target' which is required", key));
            }
            if (_type == TestType::HTTP) {
                auto url = config->config_get<std::string>("target");
                if (auto err = visor::http::validate_http_url(url)) {
                    throw NetProbeException(fmt::format("target '{}' {}", key, *err));
                }
                _http_targets[key] = url;
                if (config->config_exists("headers")) {
                    auto headers = config->config_get<std::shared_ptr<Configurable>>("headers");
                    auto hkeys = headers->get_all_keys();
                    std::vector<std::string> joined;
                    std::vector<std::string> names;
                    for (const auto &hkey : hkeys) {
                        joined.push_back(fmt::format("{}: {}", hkey, header_value_to_string(*headers, hkey)));
                        names.push_back(hkey);
                    }
                    _http_target_headers[key] = std::move(joined);
                    _http_target_header_names[key] = std::move(names);
                }
                continue;
            }
            if (_type == TestType::DOH) {
                auto url = config->config_get<std::string>("target");
                if (auto err = visor::http::validate_http_url(url)) {
                    throw NetProbeException(fmt::format("target '{}' {}", key, *err));
                }
                if (config->config_exists("headers")) {
                    throw NetProbeException("per-target 'headers' is not supported for test_type 'doh'");
                }
                _doh_targets[key] = url;
                continue;
            }
            uint32_t port{0};
            if (!config->config_exists("port") && _type == TestType::TCP) {
                throw NetProbeException(fmt::format("'{}' does not have key 'port' which is required", key));
            } else if (config->config_exists("port")) {
                port = static_cast<uint32_t>(config->config_get<uint64_t>("port"));
            }

            std::optional<bool> force_ipv6;
            if (config->config_exists("ip_version")) {
                auto v = config->config_get<uint64_t>("ip_version");
                if (v != 4 && v != 6) {
                    throw NetProbeException("ip_version must be 4 or 6");
                }
                force_ipv6 = (v == 6);
            }

            auto target = config->config_get<std::string>("target");
            if (pcpp::IPv4Address::isValidIPv4Address(target) || pcpp::IPv6Address::isValidIPv6Address(target)) {
                bool literal_v6 = pcpp::IPv6Address::isValidIPv6Address(target);
                if (force_ipv6.has_value() && *force_ipv6 != literal_v6) {
                    throw NetProbeException(fmt::format("target {} is {} but ip_version is set to {}",
                        target, literal_v6 ? "IPv6" : "IPv4", *force_ipv6 ? 6 : 4));
                }
                _ip_list[key] = IpEntry{pcpp::IPAddress(target), port};
                continue;
            }
            auto dot = target.find(".");
            if (dot == std::string::npos && target != "localhost") {
                throw NetProbeException(fmt::format("{} is an invalid/unsupported DNS", target));
            }
            _dns_list[key] = DnsEntry{target, port, force_ipv6};
        }
    }

    if (_type == TestType::DOH) {
        if (_doh_qname.empty()) {
            throw NetProbeException("netprobe: 'qname' is required when test_type is 'doh'");
        }
        // Reject names outside DNS limits (RFC 1035): total presentation length <= 253, each label
        // 1..63 chars. An invalid name would otherwise make DnsLayer::addQuery() fail at probe start.
        if (_doh_qname.size() > 253) {
            throw NetProbeException(fmt::format("netprobe: qname '{}' exceeds the 253-character DNS name limit", _doh_qname));
        }
        // "." is the DNS root — a valid name with no labels (e.g. probing the root NS set). Skip the
        // per-label checks for it; DohProbe builds the root query from an empty name.
        if (_doh_qname != ".") {
            size_t label_len = 0;
            for (char ch : _doh_qname) {
                if (ch == '.') {
                    if (label_len == 0) {
                        throw NetProbeException(fmt::format("netprobe: qname '{}' has an empty DNS label", _doh_qname));
                    }
                    label_len = 0;
                } else if (++label_len > 63) {
                    throw NetProbeException(fmt::format("netprobe: qname '{}' has a DNS label longer than 63 characters", _doh_qname));
                }
            }
            if (label_len == 0) {
                throw NetProbeException(fmt::format("netprobe: qname '{}' has an empty DNS label", _doh_qname));
            }
        }
        if (visor::lib::dns::QTypeNumbers.find(_doh_qtype) == visor::lib::dns::QTypeNumbers.end()) {
            throw NetProbeException(fmt::format("netprobe: unknown qtype '{}'", _doh_qtype));
        }
    }

    // ---- v2: scope/consistency validation ----
    // http-only keys: check each individually so the thrown message names the offending key.
    {
        static const std::vector<std::string> http_only_keys = {
            "expected_status", "failure_status", "expected_body", "expected_body_regex", "body"};
        if (_type != TestType::HTTP) {
            for (const auto &key : http_only_keys) {
                if (config_exists(key)) {
                    throw NetProbeException(fmt::format("'{}' is not supported for test_type '{}'", key, test_type_name(_type)));
                }
            }
        }
    }
    // proxy/tls are shared http+doh transport options; not meaningful for ping/tcp/udp.
    if (_type != TestType::HTTP && _type != TestType::DOH) {
        if (config_exists("proxy")) {
            throw NetProbeException("'proxy' is only supported for test_type 'http' or 'doh'");
        }
        if (config_exists("tls")) {
            throw NetProbeException("'tls' is only supported for test_type 'http' or 'doh'");
        }
    }
    // request body only makes sense paired with a method that carries one.
    if (_type == TestType::HTTP && !_http_opts.request_body.empty()) {
        if (_http_method != "POST" && _http_method != "PUT" && _http_method != "PATCH") {
            throw NetProbeException("'body' requires http_method POST, PUT, or PATCH");
        }
    }
    // client cert + key must be configured together (curl requires both or neither).
    if (_http_opts.cert_file.empty() != _http_opts.key_file.empty()) {
        throw NetProbeException("tls.cert_file and tls.key_file must be set together");
    }
    // configured TLS files must exist. std::filesystem (not access()/<unistd.h>) so this stays
    // portable to the MSVC/win64 netprobe build.
    for (const auto &[label, path] : std::vector<std::pair<std::string, std::string>>{
             {"ca_file", _http_opts.ca_file}, {"cert_file", _http_opts.cert_file}, {"key_file", _http_opts.key_file}}) {
        if (path.empty()) {
            continue;
        }
        std::error_code ec;
        if (!std::filesystem::exists(path, ec)) {
            throw NetProbeException(fmt::format("netprobe: tls.{} '{}' does not exist", label, path));
        }
    }
    // proxy, when set, must be a usable value: non-empty after trim and free of control characters
    // (which could otherwise smuggle protocol-confusing bytes). curl remains the authoritative
    // validator of the proxy URL itself at probe time. Never echo the value — it can embed credentials.
    if (!_http_opts.proxy.empty()) {
        bool has_cntrl = false;
        for (unsigned char ch : _http_opts.proxy) {
            if (std::iscntrl(ch)) {
                has_cntrl = true;
                break;
            }
        }
        if (has_cntrl || trim(_http_opts.proxy).empty()) {
            throw NetProbeException("netprobe: 'proxy' value is invalid");
        }
    }

    _create_netprobe_loop();

    _running = true;
}

void NetProbeInputStream::_send_cb(pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp)
{
    std::shared_lock lock(_input_mutex);
    for (auto &proxy : _event_proxies) {
        static_cast<NetProbeInputEventProxy *>(proxy.get())->probe_send_cb(payload, type, name, stamp);
    }
}

void NetProbeInputStream::_recv_cb(pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp)
{
    std::shared_lock lock(_input_mutex);
    for (auto &proxy : _event_proxies) {
        static_cast<NetProbeInputEventProxy *>(proxy.get())->probe_recv_cb(payload, type, name, stamp);
    }
}

void NetProbeInputStream::_fail_cb(ErrorType error, TestType type, const std::string &name)
{
    std::shared_lock lock(_input_mutex);
    for (auto &proxy : _event_proxies) {
        static_cast<NetProbeInputEventProxy *>(proxy.get())->probe_fail_cb(error, type, name);
    }
}

void NetProbeInputStream::_http_result_cb(visor::http::HttpSample sample, const std::string &name, timespec stamp)
{
    std::shared_lock lock(_input_mutex);
    for (auto &proxy : _event_proxies) {
        static_cast<NetProbeInputEventProxy *>(proxy.get())->probe_http_result_cb(sample, name, stamp);
    }
}

void NetProbeInputStream::_doh_result_cb(uint16_t http_status, uint8_t rcode, bool parse_ok, uint64_t cert_expiry_epoch, visor::http::HttpTimings t, const std::string &name, timespec stamp)
{
    std::shared_lock lock(_input_mutex);
    for (auto &proxy : _event_proxies) {
        static_cast<NetProbeInputEventProxy *>(proxy.get())->probe_doh_result_cb(http_status, rcode, parse_ok, cert_expiry_epoch, t, name, stamp);
    }
}

void NetProbeInputStream::_create_netprobe_loop()
{
    // main io loop, run in its own thread
    _io_loop = uvw::loop::create();
    if (!_io_loop) {
        throw NetProbeException("unable to create io loop");
    }
    // AsyncHandle lets us stop the loop from its own thread
    _async_h = _io_loop->resource<uvw::async_handle>();
    if (!_async_h) {
        throw NetProbeException("unable to initialize AsyncHandle");
    }
    _async_h->on<uvw::async_event>([this](const auto &, auto &handle) {
        // Stop and close the handles, then stop the loop so uv_run() returns.
        // Tear down the probe-owned handles here too, on the loop thread, so no
        // active handle remains when the loop is closed (uv_loop_close would
        // otherwise return EBUSY). Do NOT close the loop here: uv_loop_close()
        // while uv_run() is still on the stack frees structures that uv__io_poll
        // keeps using, crashing with SIGSEGV/SIGBUS. The loop is closed in the io
        // thread after run() returns.
        _timer->stop();
        _timer->close();
        for (const auto &probe : _probes) {
            if (probe) {
                probe->stop();
            }
        }
        if ((_type == TestType::HTTP || _type == TestType::DOH) && _http_client) {
            _http_client->close();
        }
        _io_loop->stop();
        handle.close();
    });
    _async_h->on<uvw::error_event>([this](const auto &err, auto &handle) {
        _logger->error("[{}] AsyncEvent error: {}", _name, err.what());
        handle.close();
    });

    if (_type == TestType::HTTP || _type == TestType::DOH) {
        _http_client = std::make_shared<visor::http::HttpClient>(_io_loop);
    }

    _timer = _io_loop->resource<uvw::timer_handle>();
    if (!_timer) {
        throw NetProbeException("unable to initialize TimerHandle");
    }
    _timer->on<uvw::timer_event>([this](const auto &, auto &) {
        timespec stamp;
        // use now()
        std::timespec_get(&stamp, TIME_UTC);
        std::shared_lock lock(_input_mutex);
        for (auto &proxy : _event_proxies) {
            proxy->heartbeat_cb(stamp);
        }
    });
    _timer->on<uvw::error_event>([this](const auto &err, auto &handle) {
        _logger->error("[{}] TimerEvent error: {}", _name, err.what());
        handle.close();
    });

    for (const auto &ip : _ip_list) {
        std::unique_ptr<NetProbe> probe{nullptr};
        if (_type == TestType::Ping) {
            probe = std::make_unique<PingProbe>(_id, ip.first, ip.second.ip, std::string());
        } else if (_type == TestType::TCP) {
            probe = std::make_unique<TcpProbe>(_id, ip.first, ip.second.ip, std::string(), ip.second.port);
        } else {
            throw NetProbeException(fmt::format("Test type currently not supported"));
        }
        ++_id;
        probe->set_configs(_interval_msec, _timeout_msec, _packets_per_test, _packets_interval_msec, _packet_payload_size);
        probe->set_callbacks([this](pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp) { _send_cb(payload, type, name, stamp); },
            [this](pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp) { _recv_cb(payload, type, name, stamp); },
            [this](ErrorType error, TestType type, const std::string &name) { _fail_cb(error, type, name); });
        probe->start(_io_loop);
        _probes.push_back(std::move(probe));
    }

    for (const auto &dns : _dns_list) {
        std::unique_ptr<NetProbe> probe{nullptr};
        if (_type == TestType::Ping) {
            probe = std::make_unique<PingProbe>(_id, dns.first, pcpp::IPAddress(), dns.second.dns, dns.second.force_ipv6);
        } else if (_type == TestType::TCP) {
            probe = std::make_unique<TcpProbe>(_id, dns.first, pcpp::IPAddress(), dns.second.dns, dns.second.port, dns.second.force_ipv6);
        } else {
            throw NetProbeException(fmt::format("Test type currently not supported"));
        }
        ++_id;
        probe->set_configs(_interval_msec, _timeout_msec, _packets_per_test, _packets_interval_msec, _packet_payload_size);
        probe->set_callbacks([this](pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp) { _send_cb(payload, type, name, stamp); },
            [this](pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp) { _recv_cb(payload, type, name, stamp); },
            [this](ErrorType error, TestType type, const std::string &name) { _fail_cb(error, type, name); });
        probe->start(_io_loop);
        _probes.push_back(std::move(probe));
    }

    for (const auto &[key, url] : _http_targets) {
        std::vector<std::string> headers;
        if (auto it = _http_target_headers.find(key); it != _http_target_headers.end()) {
            headers = it->second;
        }
        auto probe = std::make_unique<HttpProbe>(_id, key, url, _http_method, _http_client, _http_opts, headers,
            [this](visor::http::HttpSample sample, const std::string &name, timespec stamp) { _http_result_cb(sample, name, stamp); });
        ++_id;
        probe->set_configs(_interval_msec, _timeout_msec, _packets_per_test, _packets_interval_msec, _packet_payload_size);
        probe->set_callbacks([this](pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp) { _send_cb(payload, type, name, stamp); },
            [this](pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp) { _recv_cb(payload, type, name, stamp); },
            [this](ErrorType error, TestType type, const std::string &name) { _fail_cb(error, type, name); });
        probe->start(_io_loop);
        _probes.push_back(std::move(probe));
    }

    for (const auto &[key, url] : _doh_targets) {
        auto probe = std::make_unique<DohProbe>(_id, key, url, _doh_method, _doh_qname, _doh_qtype, _http_client, _http_opts,
            [this](uint16_t http_status, uint8_t rcode, bool parse_ok, uint64_t cert_expiry_epoch, visor::http::HttpTimings t, const std::string &name, timespec stamp) {
                _doh_result_cb(http_status, rcode, parse_ok, cert_expiry_epoch, t, name, stamp);
            });
        ++_id;
        probe->set_configs(_interval_msec, _timeout_msec, _packets_per_test, _packets_interval_msec, _packet_payload_size);
        probe->set_callbacks([this](pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp) { _send_cb(payload, type, name, stamp); },
            [this](pcpp::Packet &payload, TestType type, const std::string &name, timespec stamp) { _recv_cb(payload, type, name, stamp); },
            [this](ErrorType error, TestType type, const std::string &name) { _fail_cb(error, type, name); });
        probe->start(_io_loop);
        _probes.push_back(std::move(probe));
    }

    // spawn the loop
    _io_thread = std::make_unique<std::thread>([this] {
        _timer->start(uvw::timer_handle::time{1000}, uvw::timer_handle::time{HEARTBEAT_INTERVAL * 1000});
        thread::change_self_name(schema_key(), name());
        _io_loop->run();
        if (_type == TestType::Ping) {
            // Close the ping send sockets here, on the io thread that opened them: _sock/_sock6 are
            // thread_local, so this is the only thread that can actually close the raw descriptors.
            // Runs after the loop has stopped (and before stop() joins this thread), so no probe is
            // still sending.
            PingProbe::close_thread_send_sockets();
        }
        // run() has returned, so close the loop here (outside the running loop),
        // never from inside the async callback, which would crash uv__io_poll.
        // Every handle (including probe-owned ones) was closed on the loop thread
        // in the async callback, so the loop is quiescent and close() succeeds.
        _io_loop->close();
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
    // common_info_json() echoes the module's RAW config verbatim at j["module"]["config"] (via
    // Configurable::config_json). Scrub every value that can carry a secret before this JSON goes
    // anywhere: proxy URLs can embed credentials, and header/body/expected_body(_regex) values can
    // be anything the operator configured (Authorization headers, tokens in a probe body, etc.).
    // Header/proxy/body values must NEVER appear in info_json — only header/target NAMES are safe.
    if (j.contains("module") && j["module"].contains("config")) {
        auto &cfg = j["module"]["config"];
        for (const char *key : {"proxy", "body", "expected_body", "expected_body_regex"}) {
            if (cfg.contains(key)) {
                cfg[key] = "<redacted>";
            }
        }
        if (cfg.contains("targets") && cfg["targets"].is_object()) {
            for (auto &el : cfg["targets"].items()) {
                auto &tgt_val = el.value();
                if (tgt_val.is_object() && tgt_val.contains("headers") && tgt_val["headers"].is_object()) {
                    for (auto &hel : tgt_val["headers"].items()) {
                        hel.value() = "<redacted>";
                    }
                }
            }
            // Per-target header NAMES (never values) are safe to surface and useful for debugging.
            for (const auto &[tgt_name, names] : _http_target_header_names) {
                if (cfg["targets"].contains(tgt_name)) {
                    cfg["targets"][tgt_name]["header_names"] = names;
                }
            }
        }
    }
    j[schema_key()]["current_targets_total"] = _dns_list.size() + _ip_list.size() + _http_targets.size() + _doh_targets.size();
    // Report ping socket usage only for ping streams. Derive the probe count from _probes — a stable
    // per-stream member after start() — rather than a thread_local counter, which info_json (invoked
    // on an HTTP worker thread) could never read. The two addends are the shared receiver's v4 socket
    // and, when active, its v6 socket.
    if (_type == TestType::Ping && !_probes.empty()) {
        j[schema_key()]["ping_sockets"] = _probes.size() + 1 + (PingProbe::receiver_v6_active() ? 1 : 0);
    }
}

std::unique_ptr<InputEventProxy> NetProbeInputStream::create_event_proxy(const Configurable &filter)
{
    auto custom_filter = filter;
    custom_filter.config_set("xact_ttl_ms", _timeout_msec);
    return std::make_unique<NetProbeInputEventProxy>(_name, custom_filter);
}
}
