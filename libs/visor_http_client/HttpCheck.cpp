#include "HttpCheck.h"
#include <algorithm>
#include <cctype>
#include <curl/curl.h> // curl_getdate, CURL_HTTP_VERSION_* (cpp only — the header stays curl-free)
#include <nlohmann/json.hpp> // JSON pointer parsing (cpp only — the header stays nlohmann-free)
#include <stdexcept>

namespace visor::http {

static void set_range(std::vector<bool> &codes, unsigned lo, unsigned hi, const std::string &entry)
{
    if (lo < 100 || hi > 599 || lo > hi) {
        throw std::invalid_argument("invalid status entry '" + entry + "' (codes must be 100-599, ranges low-high)");
    }
    for (unsigned c = lo; c <= hi; ++c) {
        codes[c] = true;
    }
}

// Parse a decimal status code from `s`, requiring the whole string to be consumed and the value
// to be a plausible HTTP status (<= 599). Validating the unsigned-long result BEFORE narrowing to
// unsigned is essential: a value that fits in unsigned long but exceeds unsigned (e.g. 4294967496
// on LP64) would otherwise wrap to a small in-range code and be accepted. `entry` names the
// offending token in the error.
static unsigned parse_status_code(const std::string &s, const std::string &entry)
{
    try {
        size_t pos{};
        unsigned long v = std::stoul(s, &pos);
        if (pos != s.size() || v > 599) {
            throw std::invalid_argument(entry);
        }
        return static_cast<unsigned>(v);
    } catch (const std::exception &) {
        throw std::invalid_argument("invalid status entry '" + entry + "'");
    }
}

StatusMatcher StatusMatcher::parse(const std::vector<std::string> &entries)
{
    StatusMatcher m;
    for (const auto &e : entries) {
        if (e.size() == 3 && (e[1] == 'x' || e[1] == 'X') && (e[2] == 'x' || e[2] == 'X') && e[0] >= '1' && e[0] <= '5') {
            unsigned cls = static_cast<unsigned>(e[0] - '0');
            set_range(m._codes, cls * 100, cls * 100 + 99, e);
        } else if (auto dash = e.find('-'); dash != std::string::npos && dash > 0 && dash < e.size() - 1) {
            unsigned lo = parse_status_code(e.substr(0, dash), e);
            unsigned hi = parse_status_code(e.substr(dash + 1), e);
            set_range(m._codes, lo, hi, e);
        } else {
            unsigned code = parse_status_code(e, e);
            set_range(m._codes, code, code, e);
        }
        m._empty = false;
    }
    return m;
}

bool StatusMatcher::matches(uint16_t status) const
{
    return !_empty && status < _codes.size() && _codes[status];
}

bool StatusMatcher::empty() const
{
    return _empty;
}

BodyCheck BodyCheck::compile(const std::string &substr, const std::string &regex_pattern)
{
    BodyCheck b;
    b.substring = substr;
    if (!regex_pattern.empty()) {
        try {
            b.regex.emplace(regex_pattern, std::regex::ECMAScript);
        } catch (const std::regex_error &) {
            // never quote the pattern — it can embed secrets
            throw std::invalid_argument("expected_body_regex is not a valid ECMAScript regular expression");
        }
    }
    return b;
}

bool BodyCheck::matches(const std::string &body) const
{
    if (!substring.empty() && body.find(substring) == std::string::npos) {
        return false;
    }
    if (regex.has_value() && !std::regex_search(body, *regex)) {
        return false;
    }
    return true;
}

uint64_t parse_cert_expire_date(const std::string &date_str)
{
    // curl CERTINFO format, e.g. "Aug 15 12:00:00 2026 GMT" (day may be space-padded).
    // curl_getdate() is token-based (handles month-name/day/time/year/zone in any order) and,
    // unlike strptime/timegm, is fully portable incl. MSVC — netprobe builds on win64.
    if (date_str.empty()) {
        return 0;
    }
    time_t t = curl_getdate(date_str.c_str(), nullptr);
    return t > 0 ? static_cast<uint64_t>(t) : 0;
}

JsonPointerCheck JsonPointerCheck::compile(const std::string &ptr, const std::string &equals, bool equals_set)
{
    JsonPointerCheck c;
    try {
        (void)nlohmann::json::json_pointer(ptr); // validate RFC 6901 syntax
    } catch (const std::exception &) {
        throw std::invalid_argument("json_path is not a valid JSON Pointer (RFC 6901): '" + ptr + "'");
    }
    c._pointer = ptr;
    c._has_expected = equals_set;
    c._expected = equals;
    c._configured = true;
    return c;
}

bool JsonPointerCheck::configured() const
{
    return _configured;
}

bool JsonPointerCheck::matches(const std::string &body) const
{
    nlohmann::json doc = nlohmann::json::parse(body, nullptr, false); // no exceptions
    if (doc.is_discarded()) {
        return false; // not valid JSON
    }
    nlohmann::json::json_pointer p(_pointer);
    try {
        if (!doc.contains(p)) {
            return false; // pointer does not resolve
        }
        if (!_has_expected) {
            return true; // presence-only
        }
        const nlohmann::json &v = doc.at(p);
        std::string actual = v.is_string() ? v.get<std::string>() : v.dump(); // compact text for non-strings
        return actual == _expected;
    } catch (const nlohmann::json::exception &) {
        // defensive: nlohmann 3.12's contains()/at() did not throw on a deeply-missing parent in
        // observed testing, but guard against it anyway since it is not guaranteed by the API.
        return false;
    }
}

BodyNegativeCheck BodyNegativeCheck::compile(const std::string &not_substr, const std::string &not_regex_pattern)
{
    BodyNegativeCheck c;
    c.not_substring = not_substr;
    if (!not_regex_pattern.empty()) {
        try {
            c.not_regex.emplace(not_regex_pattern, std::regex::ECMAScript);
        } catch (const std::regex_error &) {
            // never quote the pattern — it can embed secrets
            throw std::invalid_argument("body_not_matches_regex is not a valid ECMAScript regular expression");
        }
    }
    return c;
}

bool BodyNegativeCheck::matches(const std::string &body) const
{
    if (!not_substring.empty() && body.find(not_substring) != std::string::npos) {
        return false;
    }
    if (not_regex.has_value() && std::regex_search(body, *not_regex)) {
        return false;
    }
    return true;
}

bool iequals_ascii(const std::string &a, const std::string &b)
{
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

HeaderMatchers HeaderMatchers::compile(const std::vector<std::pair<std::string, std::string>> &fail_if_matches,
    const std::vector<std::pair<std::string, std::string>> &fail_if_not_matches)
{
    HeaderMatchers m;
    auto build = [](const std::vector<std::pair<std::string, std::string>> &src, std::vector<HeaderMatcher> &dst) {
        for (const auto &[name, pat] : src) {
            try {
                dst.push_back(HeaderMatcher{name, std::regex(pat, std::regex::ECMAScript)});
            } catch (const std::regex_error &) {
                // never quote the pattern — it can embed secrets; name the header instead
                throw std::invalid_argument("header value_regex is not a valid ECMAScript regular expression (header '" + name + "')");
            }
        }
    };
    build(fail_if_matches, m._fail_if_matches);
    build(fail_if_not_matches, m._fail_if_not_matches);
    m._configured = !m._fail_if_matches.empty() || !m._fail_if_not_matches.empty();
    return m;
}

bool HeaderMatchers::configured() const
{
    return _configured;
}

bool HeaderMatchers::has_forbidden_rules() const
{
    return !_fail_if_matches.empty();
}

bool HeaderMatchers::matches(const std::vector<std::pair<std::string, std::string>> &headers) const
{
    for (const auto &hm : _fail_if_matches) {
        for (const auto &[hn, hv] : headers) {
            if (iequals_ascii(hn, hm.name) && std::regex_search(hv, hm.value_regex)) {
                return false; // a forbidden header matched
            }
        }
    }
    for (const auto &hm : _fail_if_not_matches) {
        bool any = false;
        for (const auto &[hn, hv] : headers) {
            if (iequals_ascii(hn, hm.name) && std::regex_search(hv, hm.value_regex)) {
                any = true;
                break;
            }
        }
        if (!any) {
            return false; // required header/value not present
        }
    }
    return true;
}

uint64_t parse_http_date(const std::string &date_str)
{
    if (date_str.empty()) {
        return 0;
    }
    time_t t = curl_getdate(date_str.c_str(), nullptr);
    return t > 0 ? static_cast<uint64_t>(t) : 0;
}

std::string http_version_name(long v)
{
    switch (v) {
    case CURL_HTTP_VERSION_1_0:
        return "1.0";
    case CURL_HTTP_VERSION_1_1:
        return "1.1";
    case CURL_HTTP_VERSION_2_0:
        return "2";
    case CURL_HTTP_VERSION_3:
        return "3";
    default:
        return "";
    }
}
}
