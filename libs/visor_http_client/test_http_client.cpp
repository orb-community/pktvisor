#include "HttpClient.h"
#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <uvw/loop.h>
#include <thread>

using namespace visor::http;

// Spin a throwaway httplib server on an ephemeral port; returns port.
static int start_test_server(httplib::Server &svr, std::thread &t)
{
    svr.Get("/ok", [](const httplib::Request &, httplib::Response &res) { res.set_content("hi", "text/plain"); });
    svr.Get("/notfound", [](const httplib::Request &, httplib::Response &res) { res.status = 404; });
    svr.Get("/error", [](const httplib::Request &, httplib::Response &res) { res.status = 500; });
    svr.Get("/slow", [](const httplib::Request &, httplib::Response &res) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        res.set_content("late", "text/plain");
    });
    svr.Post("/echo", [](const httplib::Request &req, httplib::Response &res) {
        res.set_content(req.body, "application/octet-stream");
    });
    svr.Get("/ua", [](const httplib::Request &req, httplib::Response &res) {
        res.set_content(req.get_header_value("User-Agent"), "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    t = std::thread([&svr] { svr.listen_after_bind(); });
    // Wait until the server is actually accepting connections before the test
    // connects — avoids a connect-before-listen race on slow/loaded CI machines.
    svr.wait_until_ready();
    return port;
}

// Arm a watchdog timer that calls loop->stop() after timeout_ms.
// The handle is unreferenced so loop->run() returns as soon as the real work
// handles close — the watchdog fires only if the loop would otherwise stall
// forever (hang-guard). The caller must close the returned handle after
// loop->run() completes.
static std::shared_ptr<uvw::timer_handle> arm_watchdog(std::shared_ptr<uvw::loop> loop, uint64_t timeout_ms)
{
    auto wd = loop->resource<uvw::timer_handle>();
    wd->on<uvw::timer_event>([loop](const auto &, auto &) { loop->stop(); });
    wd->start(uvw::timer_handle::time{timeout_ms}, uvw::timer_handle::time{0});
    // Unreference: the watchdog must not prevent the loop from exiting when all
    // real work handles (curl poll + timer) have closed. uv_unref makes the
    // handle "idle" w.r.t. loop liveness — the loop exits when only unreferenced
    // handles remain active, then we close the watchdog in disarm_watchdog.
    wd->unreference();
    return wd;
}

// Disarm the watchdog and drain its close on the loop.
static void disarm_watchdog(std::shared_ptr<uvw::loop> loop, std::shared_ptr<uvw::timer_handle> wd)
{
    if (wd && !wd->closing()) {
        wd->stop();
        wd->close();
        loop->run();
    }
}

// Small local RAII helper for a second (proxy) httplib server's thread lifetime; the
// richer ServerGuard in test_netprobe.cpp isn't shared with this file.
struct ServerGuard {
    httplib::Server &svr;
    std::thread &t;
    ~ServerGuard()
    {
        svr.stop();
        if (t.joinable()) t.join();
    }
};

TEST_CASE("HttpClient basic results", "[http][client]")
{
    httplib::Server svr;
    std::thread server_thread;
    int port = start_test_server(svr, server_thread);

    auto loop = uvw::loop::create();
    HttpClient client(loop);
    std::string base = "http://127.0.0.1:" + std::to_string(port);

    std::vector<HttpResult> results;
    auto on_done = [&](const HttpResult &r) { results.push_back(r); };
    // Named init (not positional aggregate) so adding HttpRequest fields doesn't warn.
    auto get_req = [](std::string url, uint64_t timeout_ms) {
        HttpRequest r;
        r.url = std::move(url);
        r.timeout_ms = timeout_ms;
        return r;
    };

    SECTION("200 OK")
    {
        client.request(get_req(base + "/ok", 2000), on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK(results[0].transport_ok);
        CHECK(results[0].status_code == 200);
        const auto &t = results[0].timings;
        CHECK(t.total_us > 0);
        // Per-phase delta sanity (plain HTTP, no TLS): the TLS phase must be 0, and every
        // phase delta must stay within the total — guards the delta arithmetic against a
        // wrong base or an unsigned underflow producing a huge bogus value.
        CHECK(t.tls_us == 0);
        CHECK(t.dns_us <= t.total_us);
        CHECK(t.connect_us <= t.total_us);
        CHECK(t.ttfb_us <= t.total_us);
    }
    SECTION("404")
    {
        client.request(get_req(base + "/notfound", 2000), on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK(results[0].transport_ok);
        CHECK(results[0].status_code == 404);
    }
    SECTION("connection refused")
    {
        client.request(get_req("http://127.0.0.1:1/x", 2000), on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK_FALSE(results[0].transport_ok);
    }
    SECTION("timeout")
    {
        client.request(get_req(base + "/slow", 100), on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK_FALSE(results[0].transport_ok);
        CHECK(results[0].curl_code == CURLE_OPERATION_TIMEDOUT);
    }
    SECTION("close while in flight")
    {
        // Issue the slow request but then immediately close() before loop->run() completes it.
        // The process must not crash and results must stay empty (interrupted = no metric recorded).
        client.request(get_req(base + "/slow", 5000), on_done);
        client.close();
        auto wd = arm_watchdog(loop, 3000);
        loop->run();
        disarm_watchdog(loop, wd);
        CHECK(results.empty());
    }

    // close() is idempotent — this is a no-op for the "close while in flight" section.
    client.close();
    loop->run();          // drain handle closes
    svr.stop();
    if (server_thread.joinable()) server_thread.join();
}

TEST_CASE("HttpClient POST body + headers + response capture", "[http][client]")
{
    httplib::Server svr;
    std::thread server_thread;
    int port = start_test_server(svr, server_thread);
    auto loop = uvw::loop::create();
    HttpClient client(loop);
    std::string base = "http://127.0.0.1:" + std::to_string(port);

    std::vector<HttpResult> results;
    auto on_done = [&](const HttpResult &r) { results.push_back(r); };

    SECTION("POST echoes body when capture_response")
    {
        HttpRequest req;
        req.url = base + "/echo";
        req.method = "POST";
        req.body = std::string("\x00\x01hello", 7); // binary-safe
        req.headers = {"Content-Type: application/octet-stream"};
        req.capture_response = true;
        req.timeout_ms = 2000;
        client.request(req, on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK(results[0].transport_ok);
        CHECK(results[0].status_code == 200);
        CHECK(results[0].response_body == std::string("\x00\x01hello", 7));
    }
    SECTION("body NOT captured by default")
    {
        HttpRequest req;
        req.url = base + "/ok";
        req.capture_response = false;
        req.timeout_ms = 2000;
        client.request(req, on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK(results[0].response_body.empty());
    }

    client.close();
    loop->run();
    svr.stop();
    if (server_thread.joinable()) server_thread.join();
}

TEST_CASE("HttpClient request() issued from within a completion callback is safe", "[http][client]")
{
    httplib::Server svr;
    std::thread server_thread;
    int port = start_test_server(svr, server_thread);

    auto loop = uvw::loop::create();
    HttpClient client(loop);
    std::string base = "http://127.0.0.1:" + std::to_string(port);

    std::vector<long> statuses;
    // In the first request's completion callback, issue a SECOND request (reentrant). The
    // _processing guard must keep this safe and let both complete.
    auto second = [&](const HttpResult &r) { statuses.push_back(r.status_code); };
    auto first = [&](const HttpResult &r) {
        statuses.push_back(r.status_code);
        HttpRequest r2;
        r2.url = base + "/notfound";
        r2.timeout_ms = 2000;
        client.request(r2, second); // reentrant: called from inside check_multi_info()'s callback fire
    };
    HttpRequest r1;
    r1.url = base + "/ok";
    r1.timeout_ms = 2000;
    client.request(r1, first);

    auto wd = arm_watchdog(loop, 5000);
    loop->run();
    disarm_watchdog(loop, wd);

    REQUIRE(statuses.size() == 2);
    CHECK(statuses[0] == 200);
    CHECK(statuses[1] == 404);

    client.close();
    loop->run();
    svr.stop();
    if (server_thread.joinable()) server_thread.join();
}

TEST_CASE("HttpClient v2 transport fields", "[http][client]")
{
    httplib::Server svr;
    std::thread server_thread;
    int port = start_test_server(svr, server_thread);
    auto loop = uvw::loop::create();
    HttpClient client(loop);
    std::string base = "http://127.0.0.1:" + std::to_string(port);
    std::vector<HttpResult> results;
    auto on_done = [&](const HttpResult &r) { results.push_back(r); };

    SECTION("user_agent is sent; response_size populated")
    {
        HttpRequest req;
        req.url = base + "/ua";
        req.user_agent = "pktvisor-test/1.0";
        req.capture_response = true;
        req.timeout_ms = 2000;
        client.request(req, on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK(results[0].response_body == "pktvisor-test/1.0");
        CHECK(results[0].response_size == results[0].response_body.size());
    }
    SECTION("plain http => cert_expiry_epoch stays 0 even when requested")
    {
        HttpRequest req;
        req.url = base + "/ok";
        req.collect_cert_info = true;
        req.timeout_ms = 2000;
        client.request(req, on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK(results[0].cert_expiry_epoch == 0);
    }
    SECTION("tls option wiring: ca/cert/key fields on a plain-http request are harmless")
    {
        // Wiring smoke: the setopts are applied without crashing and don't affect a plain-http
        // transfer (TLS options are simply unused). Real TLS validation is a manual smoke (README).
        HttpRequest req;
        req.url = base + "/ok";
        req.ca_file = "/nonexistent/ca.pem";   // paths need not exist for a plain-http transfer
        req.cert_file = "/nonexistent/c.pem";
        req.key_file = "/nonexistent/k.pem";
        req.timeout_ms = 2000;
        client.request(req, on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK(results[0].transport_ok);
        CHECK(results[0].status_code == 200);
    }
    SECTION("proxy: request goes THROUGH the forward proxy (absolute-form URI)")
    {
        httplib::Server proxy_srv;
        std::string seen_path;
        // A plain-http forward proxy receives the absolute-form request target; a regex
        // catch-all lets httplib serve it and prove the request really went via the proxy.
        proxy_srv.Get(R"((.*))", [&](const httplib::Request &preq, httplib::Response &pres) {
            seen_path = preq.path;
            pres.set_content("via-proxy", "text/plain");
        });
        int pport = proxy_srv.bind_to_any_port("127.0.0.1");
        REQUIRE(pport > 0);
        std::thread pthread([&proxy_srv] { proxy_srv.listen_after_bind(); });
        ServerGuard pguard{proxy_srv, pthread};
        proxy_srv.wait_until_ready();

        HttpRequest req;
        req.url = "http://192.0.2.1/unreachable-without-proxy"; // TEST-NET, unroutable directly
        req.proxy = "http://127.0.0.1:" + std::to_string(pport);
        req.capture_response = true;
        req.timeout_ms = 2000;
        client.request(req, on_done);
        auto wd = arm_watchdog(loop, 5000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK(results[0].transport_ok);
        CHECK(results[0].response_body == "via-proxy");
        CHECK(seen_path.find("http://192.0.2.1") == 0); // absolute-form proves proxying
    }

    client.close();
    loop->run();
    svr.stop();
    if (server_thread.joinable()) server_thread.join();
}

TEST_CASE("HttpClient body capture cap + truncation flag", "[http][client]")
{
    httplib::Server svr;
    std::string big(200 * 1024, 'a'); // 200 KB
    svr.Get("/big", [&](const httplib::Request &, httplib::Response &res) {
        res.set_content(big, "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    auto loop = uvw::loop::create();
    HttpClient client(loop);
    std::string base = "http://127.0.0.1:" + std::to_string(port);
    std::vector<HttpResult> results;
    auto on_done = [&](const HttpResult &r) { results.push_back(r); };

    SECTION("body over the cap is truncated to the cap and flagged")
    {
        HttpRequest req;
        req.url = base + "/big";
        req.capture_response = true;
        req.capture_max_bytes = 1024;
        req.timeout_ms = 3000;
        client.request(req, on_done);
        auto wd = arm_watchdog(loop, 6000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK(results[0].transport_ok);
        CHECK(results[0].body_truncated);
        CHECK(results[0].response_body.size() == 1024);
    }
    SECTION("body under the cap is complete and not flagged")
    {
        HttpRequest req;
        req.url = base + "/big";
        req.capture_response = true;
        req.capture_max_bytes = 1024 * 1024; // 1 MB > 200 KB
        req.timeout_ms = 3000;
        client.request(req, on_done);
        auto wd = arm_watchdog(loop, 6000);
        loop->run();
        disarm_watchdog(loop, wd);
        REQUIRE(results.size() == 1);
        CHECK(results[0].transport_ok);
        CHECK_FALSE(results[0].body_truncated);
        CHECK(results[0].response_body.size() == 200 * 1024);
    }

    client.close();
    loop->run();
    svr.stop();
    if (server_thread.joinable()) server_thread.join();
}

TEST_CASE("HttpClient captures response headers + http_version", "[http][client]")
{
    httplib::Server svr;
    svr.Get("/hdrs", [](const httplib::Request &, httplib::Response &res) {
        res.set_header("X-Cache", "HIT");
        res.set_content("{\"ok\":true}", "application/json");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    auto loop = uvw::loop::create();
    HttpClient client(loop);
    std::vector<HttpResult> results;
    auto on_done = [&](const HttpResult &r) { results.push_back(r); };

    HttpRequest req;
    req.url = "http://127.0.0.1:" + std::to_string(port) + "/hdrs";
    req.collect_headers = true;
    req.timeout_ms = 2000;
    client.request(req, on_done);
    auto wd = arm_watchdog(loop, 5000);
    loop->run();
    disarm_watchdog(loop, wd);

    REQUIRE(results.size() == 1);
    CHECK(results[0].transport_ok);
    CHECK(results[0].http_version != 0);
    bool found = false;
    for (auto &[n, v] : results[0].headers) {
        if (n == "X-Cache" && v == "HIT") found = true;
    }
    CHECK(found);
    CHECK_FALSE(results[0].headers_truncated); // a handful of headers is well under the cap

    client.close();
    loop->run();
    svr.stop();
    if (server_thread.joinable()) server_thread.join();
}

TEST_CASE("HttpClient flags header truncation past the capture byte cap", "[http][client]")
{
    httplib::Server svr;
    svr.Get("/many", [](const httplib::Request &, httplib::Response &res) {
        // ~1400 headers of ~64 bytes each => ~90 KB, well past the 64 KB capture cap.
        for (int i = 0; i < 1400; ++i) {
            res.set_header("X-Pad-" + std::to_string(i), std::string(48, 'y'));
        }
        res.set_content("ok", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    auto loop = uvw::loop::create();
    HttpClient client(loop);
    std::vector<HttpResult> results;
    auto on_done = [&](const HttpResult &r) { results.push_back(r); };

    HttpRequest req;
    req.url = "http://127.0.0.1:" + std::to_string(port) + "/many";
    req.collect_headers = true;
    req.timeout_ms = 3000;
    client.request(req, on_done);
    auto wd = arm_watchdog(loop, 6000);
    loop->run();
    disarm_watchdog(loop, wd);

    REQUIRE(results.size() == 1);
    CHECK(results[0].transport_ok);
    CHECK(results[0].headers_truncated); // capture stopped at the byte cap; caller must fail-safe

    client.close();
    loop->run();
    svr.stop();
    if (server_thread.joinable()) server_thread.join();
}

TEST_CASE("HttpClient response header capture resets across a redirect hop", "[http][client]")
{
    // Proves the adversarial-review finding: CURLOPT_HEADERFUNCTION fires for EVERY response in
    // the transfer (each redirect hop too). The intermediate (302) response carries a header that
    // must NOT survive into the result; only the FINAL (200) response's headers should.
    httplib::Server svr;
    svr.Get("/redir", [](const httplib::Request &, httplib::Response &res) {
        res.set_header("X-Hop", "intermediate");
        res.set_redirect("/final");
    });
    svr.Get("/final", [](const httplib::Request &, httplib::Response &res) {
        res.set_header("X-Hop", "final");
        res.set_content("done", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    auto loop = uvw::loop::create();
    HttpClient client(loop);
    std::vector<HttpResult> results;
    auto on_done = [&](const HttpResult &r) { results.push_back(r); };

    HttpRequest req;
    req.url = "http://127.0.0.1:" + std::to_string(port) + "/redir";
    req.collect_headers = true;
    req.follow_redirects = true;
    req.timeout_ms = 2000;
    client.request(req, on_done);
    auto wd = arm_watchdog(loop, 5000);
    loop->run();
    disarm_watchdog(loop, wd);

    REQUIRE(results.size() == 1);
    CHECK(results[0].transport_ok);
    CHECK(results[0].status_code == 200); // followed through to /final
    int hop_count = 0;
    std::string last_hop_value;
    for (auto &[n, v] : results[0].headers) {
        if (n == "X-Hop") {
            ++hop_count;
            last_hop_value = v;
        }
    }
    CHECK(hop_count == 1); // the intermediate hop's X-Hop must have been cleared, not appended
    CHECK(last_hop_value == "final");

    client.close();
    loop->run();
    svr.stop();
    if (server_thread.joinable()) server_thread.join();
}

TEST_CASE("HttpClient clears header-truncation flag across a redirect hop", "[http][client]")
{
    // A redirect hop with oversized headers must NOT leave headers_truncated set when the FINAL
    // response's headers fit under the cap — otherwise a header assertion that should pass on the
    // final response is failed conservatively by the probe.
    httplib::Server svr;
    svr.Get("/redir", [](const httplib::Request &, httplib::Response &res) {
        for (int i = 0; i < 1400; ++i) { // oversized intermediate headers => past the 64 KB cap
            res.set_header("X-Pad-" + std::to_string(i), std::string(48, 'z'));
        }
        res.set_redirect("/final");
    });
    svr.Get("/final", [](const httplib::Request &, httplib::Response &res) {
        res.set_header("X-Cache", "HIT"); // small final headers, comfortably under the cap
        res.set_content("done", "text/plain");
    });
    int port = svr.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    auto loop = uvw::loop::create();
    HttpClient client(loop);
    std::vector<HttpResult> results;
    auto on_done = [&](const HttpResult &r) { results.push_back(r); };

    HttpRequest req;
    req.url = "http://127.0.0.1:" + std::to_string(port) + "/redir";
    req.collect_headers = true;
    req.follow_redirects = true;
    req.timeout_ms = 3000;
    client.request(req, on_done);
    auto wd = arm_watchdog(loop, 6000);
    loop->run();
    disarm_watchdog(loop, wd);

    REQUIRE(results.size() == 1);
    CHECK(results[0].transport_ok);
    CHECK(results[0].status_code == 200);
    CHECK_FALSE(results[0].headers_truncated); // the flag from the oversized hop must have reset
    bool found = false;
    for (auto &[n, v] : results[0].headers) {
        if (n == "X-Cache" && v == "HIT") found = true;
    }
    CHECK(found);

    client.close();
    loop->run();
    svr.stop();
    if (server_thread.joinable()) server_thread.join();
}

TEST_CASE("build_connect_to_entry brackets IPv6 and reuses the original port", "[http][client]")
{
    // IPv4: address is copied verbatim; the original port is appended as PORT2.
    CHECK(build_connect_to_entry("example.com:443:1.2.3.4") == "example.com:443:1.2.3.4:443");
    // Unbracketed IPv6: the address must be bracketed for curl's HOST2 field.
    CHECK(build_connect_to_entry("example.com:443:2001:db8::1") == "example.com:443:[2001:db8::1]:443");
    // Already-bracketed IPv6: left as-is (no double brackets).
    CHECK(build_connect_to_entry("example.com:443:[2001:db8::1]") == "example.com:443:[2001:db8::1]:443");
    // IPv6 loopback (address begins immediately after the port colon).
    CHECK(build_connect_to_entry("h:80:::1") == "h:80:[::1]:80");
    // Malformed entries yield "" so the caller skips them.
    CHECK(build_connect_to_entry("host:443").empty());        // only one colon
    CHECK(build_connect_to_entry("host:443:").empty());       // empty address
    CHECK(build_connect_to_entry(":443:1.2.3.4").empty());    // empty host
    CHECK(build_connect_to_entry("host::1.2.3.4").empty());   // empty port
}

TEST_CASE("HttpClient CONNECT_TO override reaches an IPv6-loopback server", "[http][client]")
{
    // Bind on IPv6 loopback; skip where the environment has no ::1 (some CI containers).
    httplib::Server svr;
    svr.Get("/ok", [](const httplib::Request &, httplib::Response &res) { res.set_content("v6", "text/plain"); });
    int port = svr.bind_to_any_port("::1");
    if (port <= 0) {
        SKIP("no IPv6 loopback available");
    }
    std::thread server_thread([&svr] { svr.listen_after_bind(); });
    ServerGuard guard{svr, server_thread};
    svr.wait_until_ready();

    auto loop = uvw::loop::create();
    HttpClient client(loop);
    std::vector<HttpResult> results;
    auto on_done = [&](const HttpResult &r) { results.push_back(r); };

    HttpRequest req;
    // The URL host never resolves; the UNBRACKETED IPv6 resolve override must pin the connection
    // to [::1]:port. Proves build_connect_to_entry's bracketing makes curl accept the entry.
    req.url = "http://pin.invalid:" + std::to_string(port) + "/ok";
    req.resolve = {"pin.invalid:" + std::to_string(port) + ":::1"};
    req.timeout_ms = 3000;
    client.request(req, on_done);
    auto wd = arm_watchdog(loop, 6000);
    loop->run();
    disarm_watchdog(loop, wd);

    REQUIRE(results.size() == 1);
    CHECK(results[0].transport_ok);
    CHECK(results[0].status_code == 200);

    client.close();
    loop->run();
    svr.stop();
    if (server_thread.joinable()) server_thread.join();
}

TEST_CASE("HttpClient redacts proxy credentials from transport error_msg", "[http][client]")
{
    auto loop = uvw::loop::create();
    HttpClient client(loop);
    std::vector<HttpResult> results;
    auto on_done = [&](const HttpResult &r) { results.push_back(r); };

    HttpRequest req;
    req.url = "http://example.invalid/";
    // Malformed proxy (space in host) carrying credentials: curl fails and its error text can echo
    // the proxy string verbatim. The credential (and the whole proxy value) must not survive into
    // error_msg, which the probes log on transport failure.
    req.proxy = "http://user:sekrit@bad host:3128";
    req.timeout_ms = 2000;
    client.request(req, on_done);
    auto wd = arm_watchdog(loop, 5000);
    loop->run();
    disarm_watchdog(loop, wd);

    REQUIRE(results.size() == 1);
    CHECK_FALSE(results[0].transport_ok);
    CHECK(results[0].error_msg.find("sekrit") == std::string::npos);
    CHECK(results[0].error_msg.find("user:sekrit") == std::string::npos);

    client.close();
    loop->run();
}
