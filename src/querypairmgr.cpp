
#include <vector>
#include "querypairmgr.h"

namespace pktvisor {

void QueryResponsePairMgr::startDnsTransaction(uint32_t flowKey, uint16_t queryID) {
    DnsTransaction xact = {hr_clock::now()};
    _dnsTransactions[DnsXactID(flowKey, queryID)] = xact;
}

std::unique_ptr<DnsTransaction> QueryResponsePairMgr::maybeEndDnsTransaction(uint32_t flowKey, uint16_t queryID) {
    auto key = DnsXactID(flowKey, queryID);
    if (_dnsTransactions.find(key) != _dnsTransactions.end()) {
        auto result = std::make_unique<DnsTransaction>(_dnsTransactions[key]);
        _dnsTransactions.erase(key);
        return result;
    }
    else {
        return nullptr;
    }
}

void QueryResponsePairMgr::purgeOldTransactions() {
    // TODO this is a simple linear search, can optimize with some better data structures
    std::vector<DnsXactID> timed_out;
    auto now = std::chrono::high_resolution_clock::now();
    for (auto i : _dnsTransactions) {
        if (std::chrono::duration_cast<std::chrono::seconds>(now - i.second.queryStartTS).count() >= _ttl_secs) {
            timed_out.push_back(i.first);
        }
    }
    for (auto i : timed_out) {
        _dnsTransactions.erase(i);
    }
}

}
