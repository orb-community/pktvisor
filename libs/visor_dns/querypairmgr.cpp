/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "querypairmgr.h"
#include <vector>

static inline void timespec_diff(struct timespec *a, struct timespec *b,
    struct timespec *result)
{
    if (a->tv_sec > b->tv_sec) {
        result->tv_sec = a->tv_sec - b->tv_sec;
    } else {
        result->tv_sec = b->tv_sec - a->tv_sec;
    }
    result->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (result->tv_nsec < 0) {
        --result->tv_sec;
        result->tv_nsec += 1000000000L;
    }
}

namespace visor::lib::dns {

void QueryResponsePairMgr::start_transaction(uint32_t flowKey, uint16_t queryID, timespec stamp, size_t querySize)
{
    _dns_transactions[DnsXactID(flowKey, queryID)] = {stamp, {0, 0}, querySize};
}

std::pair<Result, DnsTransaction> QueryResponsePairMgr::maybe_end_transaction(uint32_t flowKey, uint16_t queryID, timespec stamp)
{
    auto key = DnsXactID(flowKey, queryID);
    if (_dns_transactions.find(key) != _dns_transactions.end()) {
        auto result = _dns_transactions[key];
        timespec_diff(&stamp, &result.queryTS, &result.totalTS);
        _dns_transactions.erase(key);
        if(result.totalTS.tv_sec >= _ttl_secs) {
            return std::pair<Result, DnsTransaction>(Result::TimedOut, result);
        } else {
            return std::pair<Result, DnsTransaction>(Result::Valid, result);
        }
    } else {
        return std::pair<Result, DnsTransaction>(Result::NotExist, DnsTransaction{{0, 0}, {0, 0}, 0});
    }
}

size_t QueryResponsePairMgr::purge_old_transactions(timespec now)
{
    // TODO this is a simple linear search, can optimize with some better data structures
    std::vector<DnsXactID> timed_out;
    for (auto i : _dns_transactions) {
        if (now.tv_sec >= _ttl_secs + i.second.queryTS.tv_sec) {
            timed_out.push_back(i.first);
        }
    }
    for (auto i : timed_out) {
        _dns_transactions.erase(i);
    }
    return timed_out.size();
}

}
