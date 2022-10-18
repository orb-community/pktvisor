/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "RequestReplyManager.h"
#include <sys/time.h>
#include <vector>

namespace visor::handler::netprobe {

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

void RequestReplyManager::start_transaction(uint16_t id, uint16_t sequence, timespec stamp, std::string target)
{
    _netprobe_transactions[id + sequence] = {target, stamp, {0, 0}};
}

std::pair<bool, NetProbeTransaction> RequestReplyManager::maybe_end_transaction(uint16_t id, uint16_t sequence, timespec stamp)
{
    uint32_t xactId = id + sequence;
    if (_netprobe_transactions.find(xactId) != _netprobe_transactions.end()) {
        auto result = _netprobe_transactions[xactId];
        timespec_diff(&stamp, &result.requestTS, &result.totalTS);
        _netprobe_transactions.erase(xactId);
        if (result.totalTS.tv_sec >= _ttl_secs) {
            return std::pair<bool, NetProbeTransaction>(false, result);
        }
        return std::pair<bool, NetProbeTransaction>(true, result);
    } else {
        return std::pair<bool, NetProbeTransaction>(false, NetProbeTransaction());
    }
}

size_t RequestReplyManager::purge_old_transactions(timespec now)
{
    std::vector<uint32_t> timed_out;
    for (auto i : _netprobe_transactions) {
        if (now.tv_sec >= _ttl_secs + i.second.requestTS.tv_sec) {
            timed_out.push_back(i.first);
        }
    }
    for (auto i : timed_out) {
        _netprobe_transactions.erase(i);
    }
    return timed_out.size();
}

}
