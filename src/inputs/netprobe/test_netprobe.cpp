#include "NetProbeInputStream.h"
#include "NetProbeStreamHandler.h"
#include "PingProbe.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <catch2/catch_test_visor.hpp>
#include <algorithm>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <thread>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/DnsResourceData.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

using namespace visor::input::netprobe;
using namespace visor::handler::netprobe;
using namespace nlohmann;
using namespace std::chrono;

TEST_CASE("NetProbe Configs", "[netprobe][ping]")
{
    // Sends real ICMP pings to localhost; needs raw-socket privileges and
    // segfaults in unprivileged CI. Only asserts the config round-trips,
    // which the config-validation tests below already cover deterministically.
    SKIP("requires raw-socket privileges");
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "ping");
    stream.config_set<uint64_t>("interval_msec", 2000);
    stream.config_set<uint64_t>("timeout_msec", 1000);
    stream.config_set<uint64_t>("packets_interval_msec", 25);
    stream.config_set<uint64_t>("packets_per_test", 2);
    stream.config_set<uint64_t>("packet_payload_size", 56);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "localhost");
    targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    CHECK_NOTHROW(stream.start());
    std::this_thread::sleep_for(1s);
    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["module"]["config"]["test_type"] == "ping");
}

TEST_CASE("NetProbe TCP config", "[netprobe][tcp]")
{
    // Resolves example.com and opens a TCP socket; segfaults in CI when DNS
    // or outbound network is restricted. Same justification as the [ping]
    // case above — the assertion is purely a config round-trip.
    SKIP("requires external network");
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "tcp");
    stream.config_set<uint64_t>("interval_msec", 500);
    stream.config_set<uint64_t>("timeout_msec", 200);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "example.com");
    target->config_set<uint64_t>("port", 80);
    targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    CHECK_NOTHROW(stream.start());
    std::this_thread::sleep_for(1s);
    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["module"]["config"]["test_type"] == "tcp");
}

TEST_CASE("NetProbe Boundaries", "[netprobe]")
{
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "ping");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "localhost");
    targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    SECTION("timeout greater than interval")
    {
        stream.config_set<uint64_t>("interval_msec", 2000);
        stream.config_set<uint64_t>("timeout_msec", 5000);
        CHECK_THROWS_WITH(stream.start(), "timeout_msec [5000] cannot be greater than interval_msec [2000]");
    }

    SECTION("huge payload size")
    {
        stream.config_set<uint64_t>("packet_payload_size", 50000000000);
        CHECK_THROWS_WITH(stream.start(), "packet_payload_size was set to 50000000000 but max supported size is 65500");
    }

    SECTION("num packets times packets interval greater than interval")
    {
        stream.config_set<uint64_t>("interval_msec", 2000);
        stream.config_set<uint64_t>("packets_interval_msec", 100);
        stream.config_set<uint64_t>("packets_per_test", 25);
        CHECK_THROWS_WITH(stream.start(), "packets_per_test [25] times packets_interval_msec [100] cannot be greater than packets_interval_msec [2000]");
    }
}

TEST_CASE("Test Configs fail", "[netprobe][config]")
{
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "ping");

    CHECK_THROWS_WITH(stream.start(), "no targets specified");
}

TEST_CASE("Netprobe invalid config", "[netprobe][config]")
{
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("invalid_config", true);

    CHECK_THROWS_WITH(stream.start(), "invalid_config is an invalid/unsupported config or filter. The valid configs/filters are: test_type, interval_msec, timeout_msec, packets_per_test, packets_interval_msec, packet_payload_size, targets, http_method, qname, qtype, expected_status, failure_status, expected_body, expected_body_regex, body, proxy, tls");
}

TEST_CASE("NetProbe ip_version config", "[netprobe][config][ipv6]")
{
    auto make = [](const std::string &tgt, std::optional<uint64_t> ipv) {
        auto targets = std::make_shared<visor::Configurable>();
        auto target = std::make_shared<visor::Configurable>();
        target->config_set("target", tgt);
        if (ipv) target->config_set<uint64_t>("ip_version", *ipv);
        targets->config_set<std::shared_ptr<visor::Configurable>>("my_target", target);
        return targets;
    };
    auto stream_with = [&](const std::shared_ptr<visor::Configurable> &targets) {
        auto s = std::make_unique<NetProbeInputStream>("net-probe-test");
        s->config_set("test_type", "ping");
        s->config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
        return s;
    };

    SECTION("invalid ip_version value") {
        auto s = stream_with(make("localhost", 5));
        CHECK_THROWS_WITH(s->start(), "ip_version must be 4 or 6");
    }
    SECTION("literal IPv4 with ip_version 6 conflicts") {
        auto s = stream_with(make("1.2.3.4", 6));
        CHECK_THROWS_WITH(s->start(), "target 1.2.3.4 is IPv4 but ip_version is set to 6");
    }
    SECTION("literal IPv6 with ip_version 4 conflicts") {
        auto s = stream_with(make("2001:db8::1", 4));
        CHECK_THROWS_WITH(s->start(), "target 2001:db8::1 is IPv6 but ip_version is set to 4");
    }
    SECTION("top-level valid-keys string unchanged") {
        NetProbeInputStream s{"net-probe-test"};
        s.config_set("invalid_config", true);
        CHECK_THROWS_WITH(s.start(), "invalid_config is an invalid/unsupported config or filter. The valid configs/filters are: test_type, interval_msec, timeout_msec, packets_per_test, packets_interval_msec, packet_payload_size, targets, http_method, qname, qtype, expected_status, failure_status, expected_body, expected_body_regex, body, proxy, tls");
    }
}

TEST_CASE("NetProbe http_method config validates", "[netprobe][config][http]")
{
    // Validates that the http_method key is accepted by validate_configs (no throw before
    // targets-missing is hit). This exercises the _config_defs registration path without
    // requiring network access or curl.
    NetProbeInputStream stream{"net-probe-test"};
    stream.config_set("test_type", "http");
    stream.config_set("http_method", std::string("GET"));
    // No targets → throws "no targets specified", NOT a config-validation error.
    // That means http_method was accepted as a valid key.
    CHECK_THROWS_WITH(stream.start(), "no targets specified");
}

TEST_CASE("NetProbe DoH config: qname required", "[netprobe][config][doh]")
{
    // test_type=doh without qname must throw the 'qname' is required error.
    NetProbeInputStream stream{"net-probe-test-doh-noqname"};
    stream.config_set("test_type", "doh");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "https://1.1.1.1/dns-query");
    targets->config_set<std::shared_ptr<visor::Configurable>>("cf_doh", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    // No qname → must throw.
    CHECK_THROWS_WITH(stream.start(), "netprobe: 'qname' is required when test_type is 'doh'");
}

TEST_CASE("NetProbe DoH config: unsupported http_method rejected", "[netprobe][config][doh]")
{
    // test_type=doh only supports GET/POST; any other method must throw a clear error.
    NetProbeInputStream stream{"net-probe-test-doh-badmethod"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set("http_method", std::string("PUT"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "https://1.1.1.1/dns-query");
    targets->config_set<std::shared_ptr<visor::Configurable>>("cf_doh", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "unsupported http_method 'PUT' for doh (use GET or POST)");
}

TEST_CASE("NetProbe DoH config: qname accepted", "[netprobe][config][doh]")
{
    // test_type=doh with qname set must pass config validation
    // (throws "no targets specified" only when targets aren't set — here we omit targets
    // to confirm that qname/qtype keys are accepted before the targets check fires).
    NetProbeInputStream stream{"net-probe-test-doh-valid"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set("qtype", std::string("A"));
    // No targets → throws "no targets specified", meaning qname/qtype were accepted as valid keys.
    CHECK_THROWS_WITH(stream.start(), "no targets specified");
}

TEST_CASE("NetProbe DoH config: qtype is normalized to uppercase", "[netprobe][config][doh]")
{
    // A lowercase qtype must be accepted (normalized to uppercase before lookup), matching the
    // rest of the codebase. Verify via the rejection message: an invalid lowercase "zzz" is
    // uppercased to "ZZZ" before the not-found error fires (which happens before any stream start).
    NetProbeInputStream stream{"net-probe-test-doh-qtype-case"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set("qtype", std::string("zzz"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "https://1.1.1.1/dns-query");
    targets->config_set<std::shared_ptr<visor::Configurable>>("cf_doh", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "netprobe: unknown qtype 'ZZZ'");
}

TEST_CASE("NetProbe DoH config: qname exceeding DNS label limit rejected", "[netprobe][config][doh]")
{
    // A label longer than 63 chars is outside DNS limits and must be rejected at config time
    // (before it reaches DnsLayer::addQuery()).
    NetProbeInputStream stream{"net-probe-test-doh-badqname"};
    stream.config_set("test_type", "doh");
    std::string long_label(64, 'a'); // 64 > 63
    stream.config_set("qname", long_label + ".example.com");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", "https://1.1.1.1/dns-query");
    targets->config_set<std::shared_ptr<visor::Configurable>>("cf_doh", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "netprobe: qname '" + long_label + ".example.com' has a DNS label longer than 63 characters");
}

TEST_CASE("NetProbe http/doh config: invalid target URL rejected", "[netprobe][config]")
{
    // A target whose URL has a non-http(s) scheme must be rejected at config time with a clear error.
    NetProbeInputStream stream{"net-probe-test-badurl"};
    stream.config_set("test_type", "http");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("ftp://example.com/x"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("bad", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "target 'bad' is not a valid http(s) URL: 'ftp://example.com/x'");
}

TEST_CASE("NetProbe v2 config: expected_status grammar errors bubble the bad entry", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-status-bad"};
    stream.config_set("test_type", "http");
    stream.config_set<visor::Configurable::StringList>("expected_status", {"2x"});
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), Catch::Matchers::ContainsSubstring("invalid status entry '2x'"));
}

TEST_CASE("NetProbe v2 config: proxy with an embedded control character is rejected without leaking the value", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-proxy-bad"};
    stream.config_set("test_type", "http");
    stream.config_set("proxy", std::string("bad\nvalue"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "netprobe: 'proxy' value is invalid");
    // A second, independent check that the raw value never appears in the exception message.
    try {
        stream.start();
        FAIL("expected NetProbeException");
    } catch (const std::exception &e) {
        CHECK_THAT(std::string(e.what()), !Catch::Matchers::ContainsSubstring("bad\nvalue"));
    }
}

TEST_CASE("NetProbe v2 config: unclosed expected_body_regex is rejected without quoting the pattern", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-regex-bad"};
    stream.config_set("test_type", "http");
    stream.config_set("expected_body_regex", std::string("(unclosed"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(),
        Catch::Matchers::ContainsSubstring("expected_body_regex") && !Catch::Matchers::ContainsSubstring("(unclosed"));
}

TEST_CASE("NetProbe v2 config: body requires a method that carries one", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-body-get"};
    stream.config_set("test_type", "http");
    stream.config_set("http_method", std::string("GET"));
    stream.config_set("body", std::string("payload"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "'body' requires http_method POST, PUT, or PATCH");
}

TEST_CASE("NetProbe v2 config: http-only keys are rejected on a doh stream", "[netprobe][config][doh]")
{
    auto make_doh_stream = [](const std::string &name) {
        auto s = std::make_unique<NetProbeInputStream>(name);
        s->config_set("test_type", "doh");
        s->config_set("qname", std::string("example.com"));
        auto targets = std::make_shared<visor::Configurable>();
        auto target = std::make_shared<visor::Configurable>();
        target->config_set("target", std::string("https://1.1.1.1/dns-query"));
        targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
        s->config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
        return s;
    };

    SECTION("expected_body")
    {
        auto s = make_doh_stream("doh-expected-body");
        s->config_set("expected_body", std::string("x"));
        CHECK_THROWS_WITH(s->start(), "'expected_body' is not supported for test_type 'doh'");
    }
    SECTION("expected_body_regex")
    {
        auto s = make_doh_stream("doh-expected-body-regex");
        s->config_set("expected_body_regex", std::string("x"));
        CHECK_THROWS_WITH(s->start(), "'expected_body_regex' is not supported for test_type 'doh'");
    }
    SECTION("body")
    {
        auto s = make_doh_stream("doh-body");
        s->config_set("body", std::string("x"));
        CHECK_THROWS_WITH(s->start(), "'body' is not supported for test_type 'doh'");
    }
    SECTION("expected_status")
    {
        auto s = make_doh_stream("doh-expected-status");
        s->config_set<visor::Configurable::StringList>("expected_status", {"200"});
        CHECK_THROWS_WITH(s->start(), "'expected_status' is not supported for test_type 'doh'");
    }
    SECTION("failure_status")
    {
        auto s = make_doh_stream("doh-failure-status");
        s->config_set<visor::Configurable::StringList>("failure_status", {"500"});
        CHECK_THROWS_WITH(s->start(), "'failure_status' is not supported for test_type 'doh'");
    }
}

TEST_CASE("NetProbe v2 config: per-target headers are not supported for doh", "[netprobe][config][doh]")
{
    NetProbeInputStream stream{"net-probe-test-doh-headers"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://1.1.1.1/dns-query"));
    auto headers = std::make_shared<visor::Configurable>();
    headers->config_set("Authorization", std::string("Bearer secret"));
    target->config_set<std::shared_ptr<visor::Configurable>>("headers", headers);
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    CHECK_THROWS_WITH(stream.start(), "per-target 'headers' is not supported for test_type 'doh'");
}

TEST_CASE("NetProbe v2 config: tls.cert_file requires tls.key_file", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-tls-xor"};
    stream.config_set("test_type", "http");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    auto tls = std::make_shared<visor::Configurable>();
    tls->config_set("cert_file", std::string("/tmp/does_not_matter.pem"));
    stream.config_set<std::shared_ptr<visor::Configurable>>("tls", tls);
    CHECK_THROWS_WITH(stream.start(), "tls.cert_file and tls.key_file must be set together");
}

TEST_CASE("NetProbe v2 config: tls.ca_file must exist", "[netprobe][config][http]")
{
    NetProbeInputStream stream{"net-probe-test-tls-ca-missing"};
    stream.config_set("test_type", "http");
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", std::string("https://example.com/"));
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
    auto tls = std::make_shared<visor::Configurable>();
    tls->config_set("ca_file", std::string("/nonexistent/ca.pem"));
    stream.config_set<std::shared_ptr<visor::Configurable>>("tls", tls);
    CHECK_THROWS_WITH(stream.start(), Catch::Matchers::ContainsSubstring("/nonexistent/ca.pem"));
}

TEST_CASE("NetProbe v2 config: proxy and tls are not supported for tcp", "[netprobe][config][tcp]")
{
    auto make_tcp_stream = [](const std::string &name) {
        auto s = std::make_unique<NetProbeInputStream>(name);
        s->config_set("test_type", "tcp");
        auto targets = std::make_shared<visor::Configurable>();
        auto target = std::make_shared<visor::Configurable>();
        target->config_set("target", std::string("example.com"));
        target->config_set<uint64_t>("port", 80);
        targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
        s->config_set<std::shared_ptr<visor::Configurable>>("targets", targets);
        return s;
    };

    SECTION("proxy")
    {
        auto s = make_tcp_stream("tcp-proxy");
        s->config_set("proxy", std::string("http://x"));
        CHECK_THROWS_WITH(s->start(), "'proxy' is only supported for test_type 'http' or 'doh'");
    }
    SECTION("tls")
    {
        auto s = make_tcp_stream("tcp-tls");
        auto tls = std::make_shared<visor::Configurable>();
        tls->config_set("verify", false);
        s->config_set<std::shared_ptr<visor::Configurable>>("tls", tls);
        CHECK_THROWS_WITH(s->start(), "'tls' is only supported for test_type 'http' or 'doh'");
    }
}

TEST_CASE("ICMPv6 reply carrier survives the fan-out Packet deep-copy", "[netprobe][ipv6]")
{
    // Wire bytes of an ICMPv6 echo REPLY: type=129, code=0, checksum=0, id=0xBEEF, seq=0x0102 (network order).
    const uint8_t reply[8] = {129, 0, 0, 0, 0xBE, 0xEF, 0x01, 0x02};

    auto carrier = build_icmpv6_reply_carrier(reply, sizeof(reply));
    REQUIRE(carrier.has_value());

    // The receiver enqueues a COPY of this Packet; the handler later does getLayerOfType<ICMPv6EchoLayer>()
    // on the copy. That deep-copy is exactly where the ICMPv6 layer used to be lost (every reply dropped).
    pcpp::Packet copy(*carrier);
    auto *echo = copy.getLayerOfType<pcpp::ICMPv6EchoLayer>();
    REQUIRE(echo != nullptr);
    CHECK(echo->getMessageType() == pcpp::ICMPv6MessageType::ICMPv6_ECHO_REPLY);
    CHECK(echo->getIdentifier() == 0xBEEF);
    CHECK(echo->getSequenceNr() == 0x0102);

    // An echo REQUEST (type 128) is not a reply and must not be enqueued.
    const uint8_t request[8] = {128, 0, 0, 0, 0xBE, 0xEF, 0x01, 0x02};
    CHECK_FALSE(build_icmpv6_reply_carrier(request, sizeof(request)).has_value());

    // A buffer shorter than the 8-byte echo header is rejected (getEchoDataLen would underflow).
    const uint8_t too_short[4] = {129, 0, 0, 0};
    CHECK_FALSE(build_icmpv6_reply_carrier(too_short, sizeof(too_short)).has_value());
}

// ---------------------------------------------------------------------------
// End-to-end HTTP probe tests: real NetProbeInputStream + NetProbeStreamHandler
// against an in-process httplib server bound to an ephemeral port.
// ---------------------------------------------------------------------------

// RAII guard: ensures httplib server is stopped and thread joined even if a
// Catch2 REQUIRE macro throws an exception that unwinds the test frame.
struct ServerGuard {
    httplib::Server &svr;
    std::thread &t;
    ~ServerGuard()
    {
        svr.stop();
        if (t.joinable()) t.join();
    }
};

TEST_CASE("NetProbe HTTP e2e: success path records attempt, success, and 200 in top_status_codes", "[netprobe][http][e2e]")
{
    // Start an in-process httplib server on an ephemeral port.
    httplib::Server svr;
    svr.Get("/ok", [](const httplib::Request &, httplib::Response &res) {
        res.set_content("ok", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/ok";

    // Configure stream: interval=500ms, timeout=400ms (timeout must not exceed interval).
    // A 500ms interval gives ≥1 tick in the 1s sleep window.
    NetProbeInputStream stream{"netprobe-http-e2e"};
    stream.config_set("test_type", "http");
    stream.config_set<uint64_t>("interval_msec", 500);
    stream.config_set<uint64_t>("timeout_msec", 400);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("ok_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    // Wire up the handler (mirrors the ping/tcp test pattern).
    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-http-e2e", proxy, &c};

    handler.start();
    stream.start();
    // Sleep generously: 1.5s covers 2+ interval ticks + request round-trip.
    std::this_thread::sleep_for(1500ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);

    REQUIRE(j.contains("targets"));
    REQUIRE(j["targets"].contains("ok_target"));
    auto &tgt = j["targets"]["ok_target"];

    CHECK(tgt["attempts"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() >= 1);

    // top_status_codes must have a "200" entry.
    REQUIRE(tgt.contains("top_status_codes"));
    bool found_200 = false;
    for (const auto &entry : tgt["top_status_codes"]) {
        if (entry.contains("name") && entry["name"] == "200") {
            found_200 = true;
        }
    }
    CHECK(found_200);
}

TEST_CASE("NetProbe v2 info_json: proxy/body/expected_body(_regex)/header values are scrubbed", "[netprobe][http][config]")
{
    // common_info_json() echoes the raw module config verbatim; without scrubbing this would leak
    // the Authorization header, the numeric header, the proxy URL, and both body-check patterns.
    httplib::Server svr;
    svr.Post("/submit", [](const httplib::Request &, httplib::Response &res) {
        res.set_content("ok", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/submit";

    NetProbeInputStream stream{"netprobe-http-redact"};
    stream.config_set("test_type", "http");
    stream.config_set("http_method", std::string("POST"));
    stream.config_set<uint64_t>("interval_msec", 500);
    stream.config_set<uint64_t>("timeout_msec", 400);
    stream.config_set("body", std::string("super-secret-payload"));
    stream.config_set("expected_body", std::string("super-secret-expected"));
    stream.config_set("expected_body_regex", std::string("^ok-[0-9]+$"));
    stream.config_set("proxy", std::string("http://proxy.invalid.example:3128"));

    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    auto headers = std::make_shared<visor::Configurable>();
    headers->config_set("Authorization", std::string("Bearer super-secret-token"));
    headers->config_set<uint64_t>("X-Request-Id", 424242);
    target->config_set<std::shared_ptr<visor::Configurable>>("headers", headers);
    targets->config_set<std::shared_ptr<visor::Configurable>>("t", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    stream.start();
    std::this_thread::sleep_for(50ms);
    stream.stop();

    nlohmann::json j;
    stream.info_json(j);
    auto &cfg = j["module"]["config"];

    CHECK(cfg["proxy"] == "<redacted>");
    CHECK(cfg["body"] == "<redacted>");
    CHECK(cfg["expected_body"] == "<redacted>");
    CHECK(cfg["expected_body_regex"] == "<redacted>");
    REQUIRE(cfg["targets"]["t"].contains("headers"));
    CHECK(cfg["targets"]["t"]["headers"]["Authorization"] == "<redacted>");
    CHECK(cfg["targets"]["t"]["headers"]["X-Request-Id"] == "<redacted>");
    REQUIRE(cfg["targets"]["t"].contains("header_names"));
    auto names = cfg["targets"]["t"]["header_names"].get<std::vector<std::string>>();
    CHECK(std::find(names.begin(), names.end(), "Authorization") != names.end());
    CHECK(std::find(names.begin(), names.end(), "X-Request-Id") != names.end());

    // Belt-and-suspenders: none of the secret literals may survive anywhere in the serialized JSON.
    std::string dump = j.dump();
    CHECK(dump.find("super-secret-token") == std::string::npos);
    CHECK(dump.find("super-secret-payload") == std::string::npos);
    CHECK(dump.find("super-secret-expected") == std::string::npos);
    CHECK(dump.find("proxy.invalid.example") == std::string::npos);
    CHECK(dump.find("424242") == std::string::npos);
    CHECK(dump.find("^ok-[0-9]+$") == std::string::npos);
    CHECK(dump.find("<redacted>") != std::string::npos);
}

TEST_CASE("NetProbe HTTP e2e: stop while request in flight does not crash or hang", "[netprobe][http][e2e]")
{
    // The slow handler sleeps 500ms — longer than our start/stop window.
    // This test verifies that stop() returns cleanly even with a curl request in flight,
    // exercising the loop-quiescent teardown of curl poll handles (_http_client->close()).
    // interval=300ms, timeout=250ms (timeout must not exceed interval); the /slow handler sleeps 500ms
    // so the request will still be in flight when we call stop() after 200ms.
    httplib::Server svr;
    svr.Get("/slow", [](const httplib::Request &, httplib::Response &res) {
        std::this_thread::sleep_for(500ms);
        res.set_content("late", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/slow";

    NetProbeInputStream stream{"netprobe-http-e2e-inflight"};
    stream.config_set("test_type", "http");
    // interval=300ms, timeout=250ms; timeout must not exceed interval.
    stream.config_set<uint64_t>("interval_msec", 300);
    stream.config_set<uint64_t>("timeout_msec", 250);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("slow_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-http-e2e-inflight", proxy, &c};

    handler.start();
    stream.start();
    // Sleep just long enough for the first request to be in flight (interval fired, curl running).
    std::this_thread::sleep_for(350ms);
    // stop() must return without hanging or crashing even though the curl request is still in flight.
    CHECK_NOTHROW(stream.stop());
    CHECK_NOTHROW(handler.stop());
}

// ---------------------------------------------------------------------------
// End-to-end DoH probe tests: real NetProbeInputStream (test_type=doh) +
// NetProbeStreamHandler against an in-process httplib server that returns a
// canned NOERROR DNS response as application/dns-message.
// ---------------------------------------------------------------------------

// Build a minimal but valid NOERROR DNS response wire-format using pcpp::DnsLayer.
// The probe only requires: size >= 12, QR==1, rcode==0.
// The EMPTY DnsLayer constructor manages its own buffer (no heap-ownership hazard here
// unlike the parse path); addAnswer with IPv4DnsResourceData is straightforward.
static std::string make_doh_response()
{
    pcpp::DnsLayer resp;
    resp.getDnsHeader()->queryOrResponse = 1;
    resp.getDnsHeader()->responseCode = 0; // NOERROR
    resp.addQuery("example.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);
    pcpp::IPv4DnsResourceData answerData(std::string("1.2.3.4"));
    resp.addAnswer("example.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN, 60, &answerData);
    return std::string(reinterpret_cast<const char *>(resp.getData()), resp.getDataLen());
}

TEST_CASE("NetProbe DoH e2e POST: success path records attempt, success, and NOERROR in top_rcodes", "[netprobe][doh][e2e]")
{
    httplib::Server svr;
    const std::string doh_body = make_doh_response();
    svr.Post("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(doh_body, "application/dns-message");
    });
    svr.Get("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(doh_body, "application/dns-message");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/dns-query";

    NetProbeInputStream stream{"netprobe-doh-e2e-post"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set("qtype", std::string("A"));
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("doh_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-doh-e2e-post", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);

    REQUIRE(j.contains("targets"));
    REQUIRE(j["targets"].contains("doh_target"));
    auto &tgt = j["targets"]["doh_target"];

    CHECK(tgt["attempts"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() >= 1);

    REQUIRE(tgt.contains("top_rcodes"));
    bool found_noerror = false;
    for (const auto &entry : tgt["top_rcodes"]) {
        if (entry.contains("name") && entry["name"] == "NOERROR") {
            found_noerror = true;
        }
    }
    CHECK(found_noerror);

    // DoH records the HTTP status breakdown (top_status_codes) too, like the HTTP probe.
    REQUIRE(tgt.contains("top_status_codes"));
    bool found_200 = false;
    for (const auto &entry : tgt["top_status_codes"]) {
        if (entry.contains("name") && entry["name"] == "200") {
            found_200 = true;
        }
    }
    CHECK(found_200);
}

TEST_CASE("NetProbe DoH e2e GET: success path records attempt, success, and NOERROR in top_rcodes", "[netprobe][doh][e2e]")
{
    httplib::Server svr;
    const std::string doh_body = make_doh_response();
    svr.Post("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(doh_body, "application/dns-message");
    });
    svr.Get("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(doh_body, "application/dns-message");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/dns-query";

    NetProbeInputStream stream{"netprobe-doh-e2e-get"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set("qtype", std::string("A"));
    stream.config_set("http_method", std::string("GET"));
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("doh_get_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-doh-e2e-get", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);

    REQUIRE(j.contains("targets"));
    REQUIRE(j["targets"].contains("doh_get_target"));
    auto &tgt = j["targets"]["doh_get_target"];

    CHECK(tgt["attempts"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() >= 1);

    REQUIRE(tgt.contains("top_rcodes"));
    bool found_noerror = false;
    for (const auto &entry : tgt["top_rcodes"]) {
        if (entry.contains("name") && entry["name"] == "NOERROR") {
            found_noerror = true;
        }
    }
    CHECK(found_noerror);

    // DoH records the HTTP status breakdown (top_status_codes) too, like the HTTP probe.
    REQUIRE(tgt.contains("top_status_codes"));
    bool found_200 = false;
    for (const auto &entry : tgt["top_status_codes"]) {
        if (entry.contains("name") && entry["name"] == "200") {
            found_200 = true;
        }
    }
    CHECK(found_200);
}

TEST_CASE("NetProbe DoH e2e: stop while request in flight does not crash or hang", "[netprobe][doh][e2e]")
{
    // The slow handler sleeps 500ms — longer than our start/stop window.
    // Mirrors the HTTP in-flight-stop test to exercise DohProbe teardown.
    httplib::Server svr;
    svr.Post("/dns-query", [](const httplib::Request &, httplib::Response &res) {
        std::this_thread::sleep_for(500ms);
        const std::string body = make_doh_response();
        res.set_content(body, "application/dns-message");
    });
    svr.Get("/dns-query", [](const httplib::Request &, httplib::Response &res) {
        std::this_thread::sleep_for(500ms);
        const std::string body = make_doh_response();
        res.set_content(body, "application/dns-message");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/dns-query";

    NetProbeInputStream stream{"netprobe-doh-e2e-inflight"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set<uint64_t>("interval_msec", 300);
    stream.config_set<uint64_t>("timeout_msec", 250);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("doh_slow_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-doh-e2e-inflight", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(350ms);
    CHECK_NOTHROW(stream.stop());
    CHECK_NOTHROW(handler.stop());
}

TEST_CASE("NetProbe DoH e2e: wrong response Content-Type is a DNS failure (not a success)", "[netprobe][doh][e2e]")
{
    // A valid DNS body returned with the WRONG Content-Type (not application/dns-message) must be
    // rejected per RFC 8484 — counted as dns_response_failures, never as a success.
    httplib::Server svr;
    const std::string doh_body = make_doh_response();
    svr.Post("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(doh_body, "text/html");
    });
    svr.Get("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(doh_body, "text/html");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/dns-query";
    NetProbeInputStream stream{"netprobe-doh-e2e-badct"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("doh_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-doh-e2e-badct", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["targets"].contains("doh_target"));
    auto &tgt = j["targets"]["doh_target"];
    CHECK(tgt["attempts"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["dns_response_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe DoH e2e: malformed DNS response body is a DNS failure (not a success)", "[netprobe][doh][e2e]")
{
    // Correct Content-Type but a body that is not a valid DNS message (too short to be a header)
    // must be rejected — counted as dns_response_failures, never as a success.
    httplib::Server svr;
    svr.Post("/dns-query", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(std::string("garbage", 7), "application/dns-message");
    });
    svr.Get("/dns-query", [](const httplib::Request &, httplib::Response &res) {
        res.set_content(std::string("garbage", 7), "application/dns-message");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/dns-query";
    NetProbeInputStream stream{"netprobe-doh-e2e-malformed"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("doh_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-doh-e2e-malformed", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["targets"].contains("doh_target"));
    auto &tgt = j["targets"]["doh_target"];
    CHECK(tgt["attempts"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["dns_response_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe DoH e2e: response declaring more answers than present is a DNS failure", "[netprobe][doh][e2e]")
{
    // NOERROR with a valid echoed question, but the header declares more answers than the body
    // contains (a truncated/incomplete answer section). pcpp parses fewer records than declared,
    // so this must be rejected, never counted as a success.
    httplib::Server svr;
    std::string body = make_doh_response(); // valid: 1 answer, ANCOUNT=1
    // Corrupt ANCOUNT (DNS header bytes 6-7, network byte order) to claim 2 answers while only 1 is present.
    REQUIRE(body.size() > 7);
    body[6] = 0x00;
    body[7] = 0x02;
    svr.Post("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(body, "application/dns-message");
    });
    svr.Get("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(body, "application/dns-message");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/dns-query";
    NetProbeInputStream stream{"netprobe-doh-e2e-truncated"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("example.com"));
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("doh_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-doh-e2e-truncated", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["targets"].contains("doh_target"));
    auto &tgt = j["targets"]["doh_target"];
    CHECK(tgt["attempts"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() == 0);
    CHECK(tgt["dns_response_failures"].get<int>() >= 1);
}

TEST_CASE("NetProbe DoH e2e: root qname (dot) probe succeeds", "[netprobe][doh][e2e]")
{
    // End-to-end root probe: qname "." must build a valid root query and match the echoed root
    // question in the response (both encode/decode as the empty name in pcpp).
    httplib::Server svr;
    // Canned NOERROR response echoing a ROOT question of type A (the probe's default qtype).
    pcpp::DnsLayer resp;
    resp.getDnsHeader()->queryOrResponse = 1;
    resp.getDnsHeader()->responseCode = 0; // NOERROR
    REQUIRE(resp.addQuery("", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN) != nullptr);
    const std::string body(reinterpret_cast<const char *>(resp.getData()), resp.getDataLen());
    svr.Post("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(body, "application/dns-message");
    });
    svr.Get("/dns-query", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(body, "application/dns-message");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    std::string url = "http://127.0.0.1:" + std::to_string(port) + "/dns-query";
    NetProbeInputStream stream{"netprobe-doh-e2e-root"};
    stream.config_set("test_type", "doh");
    stream.config_set("qname", std::string("."));
    stream.config_set<uint64_t>("interval_msec", 200);
    stream.config_set<uint64_t>("timeout_msec", 150);
    auto targets = std::make_shared<visor::Configurable>();
    auto target = std::make_shared<visor::Configurable>();
    target->config_set("target", url);
    targets->config_set<std::shared_ptr<visor::Configurable>>("doh_target", target);
    stream.config_set<std::shared_ptr<visor::Configurable>>("targets", targets);

    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    auto *proxy = stream.add_event_proxy(c);
    NetProbeStreamHandler handler{"netprobe-doh-e2e-root", proxy, &c};

    handler.start();
    stream.start();
    std::this_thread::sleep_for(750ms);
    stream.stop();
    handler.stop();

    json j;
    handler.metrics()->bucket(0)->to_json(j);
    REQUIRE(j["targets"].contains("doh_target"));
    auto &tgt = j["targets"]["doh_target"];
    CHECK(tgt["attempts"].get<int>() >= 1);
    CHECK(tgt["successes"].get<int>() >= 1);
}
