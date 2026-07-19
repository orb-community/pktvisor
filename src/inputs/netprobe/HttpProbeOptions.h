/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once
#include "HttpCheck.h"
#include <string>

namespace visor::input::netprobe {

// Shared http/doh transport + check options, parsed/validated once by NetProbeInputStream and
// handed to both probes. Lives in its own header so HttpProbe.h/DohProbe.h don't need to include
// NetProbeInputStream.h (which would create an include-surface cycle).
struct HttpProbeOptions {
    visor::http::StatusMatcher expected_status; // empty => default 2xx/3xx
    visor::http::StatusMatcher failure_status;  // empty => none
    visor::http::BodyCheck body_check;          // http only
    size_t body_check_max_bytes{512 * 1024};    // http only: cap on captured body for body checks; beyond it the check is skipped
    std::string request_body;                   // http only
    std::string proxy;
    bool tls_verify{true};
    std::string ca_file, cert_file, key_file;
    std::string user_agent; // "pktvisor/" VISOR_VERSION_NUM
};
}
