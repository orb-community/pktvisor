#include "HttpCheck.h"
#include <curl/curl.h> // curl_getdate (cpp only — the header stays curl-free)
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

StatusMatcher StatusMatcher::parse(const std::vector<std::string> &entries)
{
    StatusMatcher m;
    for (const auto &e : entries) {
        if (e.size() == 3 && (e[1] == 'x' || e[1] == 'X') && (e[2] == 'x' || e[2] == 'X') && e[0] >= '1' && e[0] <= '5') {
            unsigned cls = static_cast<unsigned>(e[0] - '0');
            set_range(m._codes, cls * 100, cls * 100 + 99, e);
        } else if (auto dash = e.find('-'); dash != std::string::npos && dash > 0 && dash < e.size() - 1) {
            unsigned lo{}, hi{};
            try {
                size_t p1{}, p2{};
                lo = static_cast<unsigned>(std::stoul(e.substr(0, dash), &p1));
                hi = static_cast<unsigned>(std::stoul(e.substr(dash + 1), &p2));
                if (p1 != dash || p2 != e.size() - dash - 1) {
                    throw std::invalid_argument(e);
                }
            } catch (const std::exception &) {
                throw std::invalid_argument("invalid status entry '" + e + "'");
            }
            set_range(m._codes, lo, hi, e);
        } else {
            unsigned code{};
            try {
                size_t pos{};
                code = static_cast<unsigned>(std::stoul(e, &pos));
                if (pos != e.size()) {
                    throw std::invalid_argument(e);
                }
            } catch (const std::exception &) {
                throw std::invalid_argument("invalid status entry '" + e + "'");
            }
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
}
