
#include <vector>
#include <sys/time.h>
#include "querypairmgr.h"

namespace pktvisor {

void QueryResponsePairMgr::startDnsTransaction(uint32_t flowKey, uint16_t queryID, timeval stamp) {
    _dnsTransactions[DnsXactID(flowKey, queryID)] = {stamp};
}

std::pair<bool, DnsTransaction> QueryResponsePairMgr::maybeEndDnsTransaction(uint32_t flowKey, uint16_t queryID, timeval stamp) {
    auto key = DnsXactID(flowKey, queryID);
    if (_dnsTransactions.find(key) != _dnsTransactions.end()) {
        auto result = _dnsTransactions[key];
        timersub(&stamp, &result.queryTS, &result.totalTS);
        _dnsTransactions.erase(key);
        return std::pair<bool, DnsTransaction>(true, result);
    }
    else {
        return std::pair<bool, DnsTransaction>(false, DnsTransaction{timeval{0,0}});
    }
}

void QueryResponsePairMgr::purgeOldTransactions(timeval now) {
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
