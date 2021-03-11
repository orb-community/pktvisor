/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <chrono>
#include <memory>
#include <unordered_map>

namespace vizer::handler::dns {

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

class QueryResponsePairMgr
{

    using DnsXactID = std::pair<uint32_t, uint16_t>;
    typedef std::unordered_map<DnsXactID, DnsTransaction, hash_pair> DnsXactMap;

    unsigned int _ttl_secs;
    DnsXactMap _dns_transactions;

public:
    QueryResponsePairMgr(unsigned int ttl_secs = 5)
        : _ttl_secs(ttl_secs)
    {
    }

    void start_transaction(uint32_t flowKey, uint16_t queryID, timespec stamp);

    std::pair<bool, DnsTransaction> maybe_end_transaction(uint32_t flowKey, uint16_t queryID, timespec stamp);

    size_t purge_old_transactions(timespec now);

    DnsXactMap::size_type open_transaction_count() const
    {
        return _dns_transactions.size();
    }
};

}

