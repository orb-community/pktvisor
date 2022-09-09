/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <chrono>
#include <memory>
#include <robin_hood.h>

namespace visor::handler::dhcp {

struct DhcpTransaction {
    timespec stamp;
    std::string hostname;
    std::string mac_address;
};

class RequestAckManager
{
    typedef robin_hood::unordered_map<uint32_t, DhcpTransaction> DhcpXactMap;

    unsigned int _ttl_secs;
    DhcpXactMap _dhcp_transactions;

public:
    RequestAckManager(unsigned int ttl_secs = 10)
        : _ttl_secs(ttl_secs)
    {
    }

    void start_transaction(uint32_t transactionID, timespec stamp, std::string hostname, std::string mac_address);

    std::pair<bool, DhcpTransaction> maybe_end_transaction(uint32_t transactionID);

    size_t purge_old_transactions(timespec now);

    DhcpXactMap::size_type open_transaction_count() const
    {
        return _dhcp_transactions.size();
    }
};

}
