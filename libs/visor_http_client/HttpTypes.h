#pragma once
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace visor::http {

struct HttpTimings {
    uint64_t total_us{0};
    uint64_t dns_us{0};
    uint64_t connect_us{0};
    uint64_t tls_us{0};
    uint64_t ttfb_us{0};
};
struct HttpRequest {
    std::string url;
    std::string method{"GET"};
    uint64_t timeout_ms{0};
    bool follow_redirects{true};
    bool verify_tls{true};
    std::string body;                   // request body bytes (empty => no body)
    std::vector<std::string> headers;   // extra request headers, each "Key: Value"
    bool capture_response{false};       // when true, capture the response body
    size_t capture_max_bytes{64 * 1024};// cap on captured response bytes; body beyond this is dropped and HttpResult.body_truncated is set
    bool collect_cert_info{false};      // when true, request CURLOPT_CERTINFO and populate HttpResult.cert_expiry_epoch
    std::string proxy;                  // CURLOPT_PROXY value (empty => no proxy)
    std::string ca_file;                // CURLOPT_CAINFO (empty => curl default CA bundle)
    std::string cert_file;              // CURLOPT_SSLCERT (client cert, empty => none)
    std::string key_file;               // CURLOPT_SSLKEY (client key, empty => none)
    std::string user_agent;             // CURLOPT_USERAGENT (empty => curl default)
    bool collect_headers{false};        // when true, capture the FINAL response's headers into HttpResult.headers
    long ip_resolve{0};                 // CURLOPT_IPRESOLVE (0 => curl default/whatever; e.g. CURL_IPRESOLVE_V4/V6)
    std::vector<std::string> resolve;   // per-target address overrides, each "host:port:address"; applied via CURLOPT_CONNECT_TO (per-handle, no shared DNS-cache leak)
};
struct HttpResult {
    bool transport_ok{false};
    long curl_code{0};
    long status_code{0};
    HttpTimings timings;
    std::string response_body;          // populated only when HttpRequest.capture_response (bounded to capture_max_bytes)
    bool body_truncated{false};         // true when the response body exceeded capture_max_bytes (response_body is a prefix)
    std::string content_type;           // raw response Content-Type header when transport_ok (compare case-insensitively)
    std::string error_msg;              // human-readable curl error detail when !transport_ok
    uint64_t cert_expiry_epoch{0};      // earliest "Expire date:" across the TLS chain when HttpRequest.collect_cert_info; 0 for plain http or on parse failure
    uint64_t response_size{0};          // CURLINFO_SIZE_DOWNLOAD_T; populated on every transport_ok, independent of capture_response
    std::vector<std::pair<std::string, std::string>> headers; // FINAL response's headers when HttpRequest.collect_headers (redirect/proxy-CONNECT hops excluded)
    bool headers_truncated{false};      // true when a header was dropped at the capture byte cap (headers is partial)
    long http_version{0};               // CURLINFO_HTTP_VERSION (e.g. CURL_HTTP_VERSION_1_1/2_0); populated on every transport_ok
};
struct HttpSample {
    uint16_t status{0};
    bool status_ok{false};        // check evaluation happens in the PROBE
    uint8_t content_check{0};     // 0 = NotChecked, 1 = Match, 2 = Mismatch
    uint64_t cert_expiry_epoch{0};
    uint64_t response_size{0};
    HttpTimings timings;
};
}
