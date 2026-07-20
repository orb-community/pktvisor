#pragma once
#include <cstdint>
#include <optional>
#include <regex>
#include <string>
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
}
