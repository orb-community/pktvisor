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

namespace pktvisor::handler::dns {

void QueryResponsePairMgr::startDnsTransaction(uint32_t flowKey, uint16_t queryID, timespec stamp)
{
    _dnsTransactions[DnsXactID(flowKey, queryID)] = {stamp};
}

std::pair<bool, DnsTransaction> QueryResponsePairMgr::maybeEndDnsTransaction(uint32_t flowKey, uint16_t queryID, timespec stamp)
{
    auto key = DnsXactID(flowKey, queryID);
    if (_dnsTransactions.find(key) != _dnsTransactions.end()) {
        auto result = _dnsTransactions[key];
        timespec_diff(&stamp, &result.queryTS, &result.totalTS);
        _dnsTransactions.erase(key);
        return std::pair<bool, DnsTransaction>(true, result);
    } else {
        return std::pair<bool, DnsTransaction>(false, DnsTransaction{timespec{0, 0}});
    }
}

void QueryResponsePairMgr::purgeOldTransactions(timespec now)
{
    // TODO this is a simple linear search, can optimize with some better data structures
    std::vector<DnsXactID> timed_out;
    for (auto i : _dnsTransactions) {
        if (now.tv_sec - i.second.queryTS.tv_sec >= _ttl_secs) {
            timed_out.push_back(i.first);
        }
    }
    for (auto i : timed_out) {
        _dnsTransactions.erase(i);
    }
}

}
