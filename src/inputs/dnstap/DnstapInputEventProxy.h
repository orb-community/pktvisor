/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif
#include "InputEventProxy.h"
#include "dnstap.pb.h"

typedef std::pair<in_addr, uint8_t> Ipv4Subnet;
typedef std::pair<in6_addr, uint8_t> Ipv6Subnet;

namespace visor::input::dnstap {

class DnstapInputEventProxy : public visor::InputEventProxy
{

    enum Filters {
        OnlyHosts,
        FiltersMAX
    };
    std::bitset<Filters::FiltersMAX> _f_enabled;

    std::vector<Ipv4Subnet> _IPv4_host_list;
    std::vector<Ipv6Subnet> _IPv6_host_list;

    bool _match_subnet(const std::string &dnstap_ip);

    void _parse_host_specs(const std::vector<std::string> &host_list);

public:
    DnstapInputEventProxy(const std::string &name, const Configurable &filter)
        : InputEventProxy(name, filter)
    {
        if (config_exists("only_hosts")) {
            _parse_host_specs(config_get<StringList>("only_hosts"));
            _f_enabled.set(Filters::OnlyHosts);
        }
    }

    ~DnstapInputEventProxy() = default;

    size_t consumer_count() const override
    {
        return policy_signal.slot_count() + heartbeat_signal.slot_count() + dnstap_signal.slot_count();
    }

    void dnstap_cb(const ::dnstap::Dnstap &dnstap, size_t size)
    {
        if (_f_enabled[Filters::OnlyHosts]) {
            if (dnstap.message().has_query_address() && dnstap.message().has_response_address()) {
                if (!_match_subnet(dnstap.message().query_address()) && !_match_subnet(dnstap.message().response_address())) {
                    // message had both query and response address, and neither matched, so filter
                    return;
                }
            } else if (dnstap.message().has_query_address() && !_match_subnet(dnstap.message().query_address())) {
                // message had only query address and it didn't match, so filter
                return;
            } else if (dnstap.message().has_response_address() && !_match_subnet(dnstap.message().response_address())) {
                // message had only response address and it didn't match, so filter
                return;
            } else {
                // message had neither query nor response address, so filter
                return;
            }
        }

        dnstap_signal(dnstap, size);
    }

    // handler functionality
    // IF THIS changes, see consumer_count()
    // note: these are mutable because consumer_count() calls slot_count() which is not const (unclear if it could/should be)
    mutable sigslot::signal<const ::dnstap::Dnstap &, size_t> dnstap_signal;
};

}