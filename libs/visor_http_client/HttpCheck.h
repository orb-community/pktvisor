#pragma once
#include <cstdint>
#include <optional>
#include <regex>
#include <string>
#include <utility>
#include <vector>

namespace visor::http {

// Parsed set of HTTP status codes (entries: "NNN", "Nxx", "A-B"). Throws std::invalid_argument
// naming the bad ENTRY (never other config values) on grammar violations.
class StatusMatcher
{
public:
    StatusMatcher() = default;                              // empty (matches nothing); empty() == true
    static StatusMatcher parse(const std::vector<std::string> &entries); // throws std::invalid_argument
    bool matches(uint16_t status) const;
    bool empty() const;

private:
    std::vector<bool> _codes = std::vector<bool>(600, false); // index by status; 100..599 valid
    bool _empty{true};
};

// Body-content checks: substring AND regex (each optional). compile() throws std::invalid_argument
// on a bad regex (message must NOT quote the pattern — patterns can embed secrets).
struct BodyCheck {
    std::string substring;                 // empty => not checked
    std::optional<std::regex> regex;       // nullopt => not checked
    bool configured() const { return !substring.empty() || regex.has_value(); }
    static BodyCheck compile(const std::string &substr, const std::string &regex_pattern); // "" => absent
    bool matches(const std::string &body) const; // AND of the configured checks
};

// Parse a curl CERTINFO "Expire date:" value, e.g. "Aug 15 12:00:00 2026 GMT", to unix epoch.
// Returns 0 on parse failure. (Pure string->epoch; the CERTINFO iteration lives in HttpClient.)
uint64_t parse_cert_expire_date(const std::string &date_str);

// RFC 6901 JSON Pointer assertion over a JSON body.
class JsonPointerCheck
{
public:
    JsonPointerCheck() = default;                       // not configured; configured()==false
    // ptr: RFC 6901 pointer (validated; throws std::invalid_argument if malformed).
    // equals_set=false => presence-only (pointer must resolve). equals_set=true => value's
    // string form must equal `equals`.
    static JsonPointerCheck compile(const std::string &ptr, const std::string &equals, bool equals_set);
    bool configured() const;
    bool matches(const std::string &body) const;        // true = PASS
private:
    std::string _pointer;
    bool _has_expected{false};
    std::string _expected;
    bool _configured{false};
};

// Inverse body assertions: body must NOT contain `substring` and must NOT match `regex`.
struct BodyNegativeCheck {
    std::string not_substring;                 // empty => not checked
    std::optional<std::regex> not_regex;       // nullopt => not checked
    bool configured() const { return !not_substring.empty() || not_regex.has_value(); }
    static BodyNegativeCheck compile(const std::string &not_substr, const std::string &not_regex_pattern);
    bool matches(const std::string &body) const; // true = PASS (neither negative hit)
};

// Response-header assertions (fail_if_header_matches / fail_if_header_not_matches).
struct HeaderMatcher {
    std::string name;         // case-insensitive header name
    std::regex value_regex;   // compiled ECMAScript
};
class HeaderMatchers
{
public:
    // Each pair is (name, value_regex_pattern). compile throws std::invalid_argument on a bad
    // pattern (never quoting it). fail_if_matches: PASS unless some header `name` value matches.
    // fail_if_not_matches: PASS only if some header `name` value matches.
    static HeaderMatchers compile(const std::vector<std::pair<std::string, std::string>> &fail_if_matches,
                                  const std::vector<std::pair<std::string, std::string>> &fail_if_not_matches);
    bool configured() const;
    // True when any fail_if_matches (forbidden-header) rule is configured. A forbidden-header PASS is
    // only "no match seen in the captured headers", so it cannot be trusted when capture truncated;
    // a required-header (fail_if_not_matches) PASS is a positive presence proof that truncation
    // cannot invalidate. The probe uses this to decide whether to fail-safe on truncation.
    bool has_forbidden_rules() const;
    // headers: response headers as (name,value); name compared case-insensitively.
    bool matches(const std::vector<std::pair<std::string, std::string>> &headers) const; // true = PASS
private:
    std::vector<HeaderMatcher> _fail_if_matches;
    std::vector<HeaderMatcher> _fail_if_not_matches;
    bool _configured{false};
};

// Parse an HTTP-date (Last-Modified) to unix epoch via curl_getdate; 0 on failure/empty.
uint64_t parse_http_date(const std::string &date_str);

// Map CURLINFO_HTTP_VERSION (CURL_HTTP_VERSION_*) to "1.0"/"1.1"/"2"/"3"/"" (unknown).
std::string http_version_name(long curl_http_version);

// Portable ASCII case-insensitive equality (no strcasecmp — MSVC). Used for header-name matching
// here and by the probe's Last-Modified lookup (Task 5).
bool iequals_ascii(const std::string &a, const std::string &b);
}
