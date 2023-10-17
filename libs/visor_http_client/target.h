#pragma once

#include <string>

struct http_parser_url;

struct Target {
    http_parser_url *parsed;
    std::string address;
    std::string uri;
};
