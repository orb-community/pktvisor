/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once
#include <nlohmann/json.hpp>
#include <sstream>
#include <timer.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <kll_sketch.hpp>
#pragma GCC diagnostic pop
#include <chrono>
#include <shared_mutex>

namespace visor {

using json = nlohmann::json;
using namespace std::chrono;

typedef datasketches::kll_sketch<long> QuantileType;

class Metric
{
protected:
    std::string _name;
    std::string _desc;

public:
    Metric(std::string name, std::string desc)
        : _name(std::move(name))
        , _desc(std::move(desc))
    {
    }

    void set_info(const std::string &name, const std::string &desc)
    {
        _name = name;
        _desc = desc;
    }

    virtual void to_json(json &j) const = 0;
    virtual void to_prometheus(std::stringstream &out, const std::string &key) const = 0;
};

/**
 * A Counter metric class which knows how to render its output
 * NOTE: intentionally _not_ thread safe; it should be protected by a mutex
 */
class Counter final : public Metric
{
    uint64_t _value = 0;

public:
    Counter(std::string name, std::string desc)
        : Metric(std::move(name), std::move(desc))
    {
    }

    Counter &operator++()
    {
        ++_value;
        return *this;
    }

    uint64_t value() const
    {
        return _value;
    }

    void operator+=(const Counter &other)
    {
        _value += other._value;
    }

    // Metric
    virtual void to_json(json &j) const override;
    virtual void to_prometheus(std::stringstream &out, const std::string &key) const override;
};

class Rate final : public Metric
{
    std::atomic_uint64_t _counter;
    std::atomic_uint64_t _rate;
    mutable std::shared_mutex _sketch_mutex;
    QuantileType _quantile;

    std::shared_ptr<timer::interval_handle> _timer_handle;

public:
    Rate(std::string name, std::string desc)
        : Metric(std::move(name), std::move(desc))
        , _counter(0)
        , _rate(0)
        , _quantile()
    {
        _quantile = QuantileType();
        // all rates use a single static timer object which holds its own thread
        // the tick argument determines the granularity of job running and canceling
        static timer timer_thread{100ms};
        _timer_handle = timer_thread.set_interval(1s, [this] {
            _rate.store(_counter.exchange(0));
            // lock mutex for write
            std::unique_lock lock(_sketch_mutex);
            _quantile.update(_rate);
        });
    }

    ~Rate()
    {
        _timer_handle->cancel();
    }

    /**
     * stop rate collection, ie. expect no more counter updates.
     * does not affect the quantiles - in effect, it makes the rate read only
     * must be thread safe
     */
    void cancel()
    {
        _timer_handle->cancel();
        _rate.store(0, std::memory_order_relaxed);
        _counter.store(0, std::memory_order_relaxed);
    }

    Rate &operator++()
    {
        _counter.fetch_add(1, std::memory_order_relaxed);
        return *this;
    }

    uint64_t counter() const
    {
        return _counter.load(std::memory_order_relaxed);
    }

    uint64_t rate() const
    {
        return _rate.load(std::memory_order_relaxed);
    }

    void merge(const Rate &other)
    {
        std::shared_lock r_lock(other._sketch_mutex);
        std::unique_lock w_lock(_sketch_mutex);
        _quantile.merge(other._quantile);
        // the live rate to simply copied if non zero
        if (other._rate != 0) {
            _rate.store(other._rate, std::memory_order_relaxed);
        }
    }

    void to_json(json &j, bool include_live) const;

    // Metric
    virtual void to_json(json &j) const override;
    virtual void to_prometheus(std::stringstream &out, const std::string &key) const override;
};

}