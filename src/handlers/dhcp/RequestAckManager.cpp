/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "RequestAckManager.h"
#include <vector>

namespace visor::handler::dhcp {

void RequestAckManager::start_transaction(uint32_t transactionID, timespec stamp, std::string hostname, std::string mac_address)
{
    _dhcp_transactions[transactionID] = {stamp, hostname, mac_address};
}

std::pair<bool, DhcpTransaction> RequestAckManager::maybe_end_transaction(uint32_t transactionID)
{
    if (_dhcp_transactions.find(transactionID) != _dhcp_transactions.end()) {
        auto result = _dhcp_transactions[transactionID];
        _dhcp_transactions.erase(transactionID);
        return std::pair<bool, DhcpTransaction>(true, result);
    } else {
        return std::pair<bool, DhcpTransaction>(false, DhcpTransaction());
    }
}

size_t RequestAckManager::purge_old_transactions(timespec now)
{
    std::vector<uint32_t> timed_out;
    for (auto i : _dhcp_transactions) {
        if (now.tv_sec >= _ttl_secs + i.second.stamp.tv_sec) {
            timed_out.push_back(i.first);
        }
    }
    for (auto i : timed_out) {
        _dhcp_transactions.erase(i);
    }
    return timed_out.size();
}

}
