/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <chrono>
#include <memory>
#include "LRUList.h"

namespace visor::handler::dns {

struct DnsTransaction {
    timespec queryTS;
    timespec totalTS;
};

class QueryResponsePairMgr
{

    using DnsXactID = std::pair<uint32_t, uint16_t>;
    typedef pcpp::LRUList<DnsXactID, DnsTransaction> DnsXactMap;

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

    size_t open_transaction_count() const
    {
        return _dns_transactions.getSize();
    }
};

}

