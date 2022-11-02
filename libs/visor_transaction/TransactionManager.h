/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "robin_hood.h"
#include <chrono>
#include <memory>

namespace visor::lib::transaction {

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

enum class Result {
    NotExist,
    TimedOut,
    Valid
};

struct Transaction {
    timespec startTS;
    timespec totalTS{0, 0};
};

template <typename XactID, typename TransactionType, typename Hash = hash_pair>
class TransactionManager
{
    static_assert(std::is_base_of<Transaction, TransactionType>::value, "TransactionType must inherit from Transaction structure");
    typedef robin_hood::unordered_map<XactID, TransactionType, Hash> XactMap;

    unsigned int _ttl_secs;
    XactMap _transactions;

public:
    TransactionManager(unsigned int ttl_secs = 5)
        : _ttl_secs(ttl_secs)
    {
    }

    void start_transaction(XactID id, TransactionType type)
    {
        _transactions[id] = type;
    }

    std::pair<Result, TransactionType> maybe_end_transaction(XactID id, timespec endTS)
    {
        if (_transactions.find(id) != _transactions.end()) {
            auto result = _transactions[id];
            timespec_diff(&endTS, &result.startTS, &result.totalTS);
            _transactions.erase(id);
            if (result.totalTS.tv_sec >= _ttl_secs) {
                return std::pair<Result, TransactionType>(Result::TimedOut, result);
            } else {
                return std::pair<Result, TransactionType>(Result::Valid, result);
            }
        } else {
            return std::pair<Result, TransactionType>(Result::NotExist, TransactionType());
        }
    }

    size_t purge_old_transactions(timespec now)
    {
        std::vector<XactID> timed_out;
        for (auto i : _transactions) {
            if (now.tv_sec >= _ttl_secs + i.second.startTS.tv_sec) {
                timed_out.push_back(i.first);
            }
        }
        for (auto i : timed_out) {
            _transactions.erase(i);
        }
        return timed_out.size();
    }

    typename XactMap::size_type open_transaction_count() const
    {
        return _transactions.size();
    }
};

}
