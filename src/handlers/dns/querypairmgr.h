#ifndef PKTVISOR3_QUERYPAIRMGR_H
#define PKTVISOR3_QUERYPAIRMGR_H

#include <chrono>
#include <memory>
#include <unordered_map>

namespace pktvisor::handler::dns {

using hr_clock = std::chrono::high_resolution_clock;

// A hash function used to hash a pair of any kind
struct hash_pair {
    template <class T1, class T2>
    size_t operator()(const std::pair<T1, T2> &p) const
    {
        auto hash1 = std::hash<T1>{}(p.first);
        auto hash2 = std::hash<T2>{}(p.second);
        return hash1 ^ hash2;
    }
};

struct DnsTransaction {
    timespec queryTS;
    timespec totalTS;
};

// TODO not thread safe
class QueryResponsePairMgr
{

    using DnsXactID = std::pair<uint32_t, uint16_t>;
    typedef std::unordered_map<DnsXactID, DnsTransaction, hash_pair> DnsXactMap;

    unsigned int _ttl_secs;
    DnsXactMap _dnsTransactions;

public:
    QueryResponsePairMgr(unsigned int ttl_secs = 5)
        : _ttl_secs(ttl_secs)
    {
    }
    void startDnsTransaction(uint32_t flowKey, uint16_t queryID, timespec stamp);
    std::pair<bool, DnsTransaction> maybeEndDnsTransaction(uint32_t flowKey, uint16_t queryID, timespec stamp);
    void purgeOldTransactions(timespec now);
    DnsXactMap::size_type getOpenTransactionCount() const
    {
        return _dnsTransactions.size();
    }
};

}

#endif //PKTVISOR3_QUERYPAIRMGR_H
