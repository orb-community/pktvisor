/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "querypairmgr.h"
#include <sys/time.h>
#include <vector>

static inline void timespec_diff(struct timespec *a, struct timespec *b,
    struct timespec *result)
{
    result->tv_sec = a->tv_sec - b->tv_sec;
    result->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (result->tv_nsec < 0) {
        --result->tv_sec;
        result->tv_nsec += 1000000000L;
    }
}

namespace visor::handler::dns {

void QueryResponsePairMgr::start_transaction(uint32_t flowKey, uint16_t queryID, timespec stamp)
{
    _dns_transactions.put(DnsXactID(flowKey, queryID), {stamp, {0, 0}});
}

std::pair<bool, DnsTransaction> QueryResponsePairMgr::maybe_end_transaction(uint32_t flowKey, uint16_t queryID, timespec stamp)
{
    auto key = DnsXactID(flowKey, queryID);
    auto value = _dns_transactions.getElement(key);
    if (value.has_value()) {
        auto result = value.value().second;
        timespec_diff(&stamp, &result.queryTS, &result.totalTS);
        _dns_transactions.eraseElement(key);
        return std::pair<bool, DnsTransaction>(true, result);
    } else {
        return std::pair<bool, DnsTransaction>(false, DnsTransaction{{0, 0}, {0, 0}});
    }
}

size_t QueryResponsePairMgr::purge_old_transactions(timespec now)
{
    size_t timed_out = 0;
    for (;;) {
        auto last_transaction = _dns_transactions.getLRUElement();
        if (now.tv_sec < last_transaction.second.queryTS.tv_sec + _ttl_secs) {
            break;
        }
        _dns_transactions.eraseElement(last_transaction.first);
        ++timed_out;
    }
    return timed_out;
}

}
