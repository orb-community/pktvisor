/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "dns.h"

namespace visor::handler::dns {

AggDomainResult aggregateDomain(const std::string &domain)
{

    std::string_view qname2(domain);
    std::string_view qname3(domain);

    // smallest we ever agg is a.b.c which returns a.b.c and b.c
    if (domain.size() < 5) {
        qname3.remove_prefix(domain.size());
        return AggDomainResult(qname2, qname3);
    }
    std::size_t endDot = std::string::npos;
    if (domain.back() == '.') {
        endDot = domain.size() - 2;
    }
    auto first_dot = domain.rfind('.', endDot);
    if (first_dot != std::string::npos && first_dot > 0) {
        auto second_dot = domain.rfind('.', first_dot - 1);
        if (second_dot != std::string::npos) {
            qname2.remove_prefix(second_dot);
            if (second_dot > 0) {
                auto third_dot = domain.rfind('.', second_dot - 1);
                if (third_dot != std::string::npos) {
                    qname3.remove_prefix(third_dot);
                }
            }
        } else {
            // didn't find two dots, so this is empty
            qname3.remove_prefix(domain.size());
        }
    }
    return AggDomainResult(qname2, qname3);
}

}