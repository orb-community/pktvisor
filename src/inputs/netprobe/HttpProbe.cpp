/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "HttpProbe.h"
#include "NetProbeException.h"
#include <spdlog/spdlog.h>

namespace visor::input::netprobe {

bool HttpProbe::start(std::shared_ptr<uvw::loop> io_loop)
{
    if (_init || _url.empty()) {
        return false;
    }
    _io_loop = io_loop;
    _interval_timer = _io_loop->resource<uvw::timer_handle>();
    if (!_interval_timer) {
        throw NetProbeException("Netprobe - unable to initialize interval TimerHandle");
    }
    _interval_timer->on<uvw::timer_event>([this](const auto &, auto &) {
        // The outer timer lambda captures `this` — safe because the interval timer is
        // stopped and closed on the loop thread (HttpProbe::stop()) before the probe is
        // destroyed, and the loop is single-threaded, so no timer event fires after stop().
        // The inner completion callback captures _http_result/_fail BY VALUE so it can run
        // after this timer tick returns without referencing the probe.
        visor::http::HttpRequest req;
        req.url = _url;
        req.method = _method;
        req.timeout_ms = _config.timeout_msec;
        req.body = _opts.request_body;
        req.headers = _headers;
        // Do NOT follow redirects when the probe carries potentially-secret payload:
        //  - custom request headers: libcurl re-sends them on followed redirects (it only strips a
        //    few built-ins like Authorization/Cookie) with no per-host scoping, so a 30x to another
        //    host would leak an operator's secret header (e.g. X-Api-Key);
        //  - a request body: a 307/308 preserves the method and body, re-sending the (redacted,
        //    potentially secret) payload to the redirect target.
        // In either case the 30x is reported as the result instead. (DoH is unaffected — its only
        // headers are the fixed, non-secret Content-Type/Accept, and it sends no operator body.)
        req.follow_redirects = _headers.empty() && _opts.request_body.empty();
        req.proxy = _opts.proxy;
        req.ca_file = _opts.ca_file;
        req.cert_file = _opts.cert_file;
        req.key_file = _opts.key_file;
        req.user_agent = _opts.user_agent;
        req.verify_tls = _opts.tls_verify;
        req.collect_cert_info = true;
        req.capture_response = _opts.body_check.configured() || _opts.json_check.configured() || _opts.body_negative.configured();
        req.capture_max_bytes = _opts.body_check_max_bytes;
        req.collect_headers = _opts.header_matchers.configured() || _opts.max_last_modified_diff > 0;
        req.ip_resolve = _ip_resolve;
        req.resolve = _resolve;
        const std::string name = _name;
        auto http_result = _http_result;
        auto fail = _fail;
        auto opts = _opts; // copyable (regex copies are fine at probe frequency); no `this` in completion lambda
        auto cert_cache = _cert_cache;
        _client->request(req, [http_result, fail, name, opts, cert_cache](const visor::http::HttpResult &r) {
            timespec stamp;
            std::timespec_get(&stamp, TIME_UTC);
            if (r.transport_ok) {
                visor::http::HttpSample s;
                s.status = static_cast<uint16_t>(r.status_code);
                bool status_ok;
                if (opts.failure_status.matches(s.status)) {
                    status_ok = false;
                } else if (!opts.expected_status.empty()) {
                    status_ok = opts.expected_status.matches(s.status);
                } else {
                    status_ok = (s.status >= 200 && s.status < 400);
                }
                s.status_ok = status_ok;
                s.content_check = 0;
                if (status_ok) {
                    bool checked = false, pass = true;
                    // Body-based assertions: skipped (inconclusive) if the body was truncated. A
                    // partial body can't authoritatively pass/fail a substring/regex/JSON/negative
                    // check — a match beyond the cap would be missed, and an anchored regex could
                    // match the artificial truncation boundary.
                    bool body_assertions = opts.body_check.configured() || opts.json_check.configured() || opts.body_negative.configured();
                    if (body_assertions) {
                        if (r.body_truncated) {
                            // A forbidden substring VISIBLE in the captured prefix is a definitive
                            // failure even on a truncated body — substring presence does not depend on
                            // the unseen tail. The other body assertions (positive matches, regex, and
                            // JSON parsing) stay inconclusive on a partial body and are skipped.
                            if (opts.body_negative.configured() && !opts.body_negative.not_substring.empty()
                                && r.response_body.find(opts.body_negative.not_substring) != std::string::npos) {
                                checked = true;
                                pass = false;
                            } else if (auto logger = spdlog::get("visor")) {
                                logger->warn("netprobe http[{}]: response body exceeded the {}-byte capture limit; body assertions skipped (raise body_check_max_bytes)", name, opts.body_check_max_bytes);
                            }
                        } else {
                            checked = true;
                            if (opts.body_check.configured() && !opts.body_check.matches(r.response_body)) {
                                pass = false;
                            }
                            if (pass && opts.json_check.configured() && !opts.json_check.matches(r.response_body)) {
                                pass = false;
                            }
                            if (pass && opts.body_negative.configured() && !opts.body_negative.matches(r.response_body)) {
                                pass = false;
                            }
                        }
                    }
                    // Size bounds (use the true downloaded size, always exact — unaffected by capture
                    // truncation).
                    if (opts.min_response_size || opts.max_response_size) {
                        checked = true;
                        if (opts.min_response_size && r.response_size < *opts.min_response_size) {
                            pass = false;
                        }
                        if (pass && opts.max_response_size && r.response_size > *opts.max_response_size) {
                            pass = false;
                        }
                    }
                    // Response-header matchers.
                    if (pass && opts.header_matchers.configured()) {
                        checked = true;
                        if (!opts.header_matchers.matches(r.headers)) {
                            pass = false;
                        } else if (r.headers_truncated) {
                            // Some response headers were dropped at the capture cap, so a "pass" can't
                            // be trusted (a forbidden header could be among the dropped ones). Fail
                            // conservatively rather than silently succeed.
                            pass = false;
                            if (auto logger = spdlog::get("visor")) {
                                logger->warn("netprobe http[{}]: response headers exceeded the capture limit; header assertion failed conservatively", name);
                            }
                        }
                    }
                    // Last-Modified freshness.
                    if (pass && opts.max_last_modified_diff > 0) {
                        checked = true;
                        uint64_t lm = 0;
                        for (const auto &[hn, hv] : r.headers) {
                            if (visor::http::iequals_ascii(hn, "Last-Modified")) {
                                lm = visor::http::parse_http_date(hv);
                                break;
                            }
                        }
                        uint64_t now = static_cast<uint64_t>(stamp.tv_sec);
                        if (lm == 0 || (now > lm && now - lm > opts.max_last_modified_diff)) {
                            pass = false;
                        }
                    }
                    // Negotiated HTTP version.
                    if (pass && !opts.valid_http_versions.empty()) {
                        checked = true;
                        std::string ver = visor::http::http_version_name(r.http_version);
                        bool ok = false;
                        for (const auto &allowed : opts.valid_http_versions) {
                            if (allowed == ver) {
                                ok = true;
                                break;
                            }
                        }
                        if (!ok) {
                            pass = false;
                        }
                    }
                    if (checked) {
                        s.content_check = pass ? 1 : 2;
                    }
                }
                // CERTINFO is only filled on transfers that performed a TLS handshake; reused
                // pooled connections report nothing. Cache the last known expiry per target so
                // EVERY sample carries it and the metric doesn't flap with connection reuse.
                if (r.cert_expiry_epoch != 0) {
                    *cert_cache = r.cert_expiry_epoch;
                }
                s.cert_expiry_epoch = (r.cert_expiry_epoch != 0) ? r.cert_expiry_epoch : *cert_cache;
                s.response_size = r.response_size;
                s.timings = r.timings;
                http_result(s, name, stamp);
            } else {
                if (auto logger = spdlog::get("visor")) {
                    logger->debug("netprobe http[{}]: transport error: {} (curl code {})", name, r.error_msg, r.curl_code);
                }
                ErrorType err = ErrorType::SocketError;
                if (r.curl_code == CURLE_COULDNT_RESOLVE_HOST || r.curl_code == CURLE_COULDNT_RESOLVE_PROXY) {
                    err = ErrorType::DnsLookupFailure;
                } else if (r.curl_code == CURLE_COULDNT_CONNECT) {
                    err = ErrorType::ConnectFailure;
                } else if (r.curl_code == CURLE_OPERATION_TIMEDOUT) {
                    err = ErrorType::Timeout;
                }
                fail(err, TestType::HTTP, name);
            }
        });
    });
    _interval_timer->start(uvw::timer_handle::time{0}, uvw::timer_handle::time{_config.interval_msec});
    _init = true;
    return true;
}

bool HttpProbe::stop()
{
    // Called on the loop thread (matches the netprobe loop-quiescent teardown).
    if (_interval_timer && !_interval_timer->closing()) {
        _interval_timer->stop();
        _interval_timer->close();
    }
    return true;
}
}
