/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once
#include <nlohmann/json.hpp>
#include <sstream>
#include <timer.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wrange-loop-analysis"
#include <cpc_sketch.hpp>
#include <frequent_items_sketch.hpp>
#include <kll_sketch.hpp>
#pragma GCC diagnostic pop
#include <chrono>
#include <shared_mutex>
#include <vector>

namespace visor {

using json = nlohmann::json;
using namespace std::chrono;

class Metric
{
protected:
    std::vector<std::string> _name;
    std::string _desc;

public:
    Metric(std::initializer_list<std::string> names, std::string desc)
        : _name(names)
        , _desc(std::move(desc))
    {
    }

    void set_info(std::initializer_list<std::string> names, const std::string &desc)
    {
        _name.clear();
        _name = names;
        _desc = desc;
    }

    void name_json_assign(json &j, const json &val) const;
    void name_json_assign(json &j, std::initializer_list<std::string> add_names, const json &val) const;

    [[nodiscard]] std::string name_snake() const
    {
        return std::accumulate(std::begin(_name), std::end(_name), std::string(),
            [](const std::string &ss, const std::string &s) {
                return ss.empty() ? s : ss + "_" + s;
            });
    }

    virtual void to_json(json &j) const = 0;
    virtual void to_prometheus(std::stringstream &out) const = 0;
};

/**
 * A Counter metric class which knows how to render its output
 * NOTE: intentionally _not_ thread safe; it should be protected by a mutex
 */
class Counter final : public Metric
{
    uint64_t _value = 0;

public:
    Counter(std::initializer_list<std::string> names, std::string desc)
        : Metric(names, std::move(desc))
    {
    }

    Counter &operator++()
    {
        ++_value;
        return *this;
    }

    [[nodiscard]] uint64_t value() const
    {
        return _value;
    }

    void operator+=(uint64_t i)
    {
        _value += i;
    }

    void operator+=(const Counter &other)
    {
        _value += other._value;
    }

    // Metric
    void to_json(json &j) const override;
    void to_prometheus(std::stringstream &out) const override;
};

/**
 * A Quantile metric class which knows how to render its output into p50, p90, p95, p99
 *
 * NOTE: intentionally _not_ thread safe; it should be protected by a mutex
 */
template <typename T>
class Quantile final : public Metric
{
    datasketches::kll_sketch<T> _quantile;

public:
    Quantile(std::initializer_list<std::string> names, std::string desc)
        : Metric(names, std::move(desc))
    {
    }

    void update(const T &value)
    {
        _quantile.update(value);
    }

    void update(T &&value)
    {
        _quantile.update(value);
    }

    void merge(const Quantile &other)
    {
        _quantile.merge(other._quantile);
    }

    auto get_n() const
    {
        return _quantile.get_n();
    }

    auto get_quantile(float p) const
    {
        return _quantile.get_quantile(p);
    }

    // Metric
    void to_json(json &j) const override
    {
        const double fractions[4]{0.50, 0.90, 0.95, 0.99};

        auto quantiles = _quantile.get_quantiles(fractions, 4);
        if (quantiles.size()) {
            name_json_assign(j, {"p50"}, quantiles[0]);
            name_json_assign(j, {"p90"}, quantiles[1]);
            name_json_assign(j, {"p95"}, quantiles[2]);
            name_json_assign(j, {"p99"}, quantiles[3]);
        }
    }

    void to_prometheus(std::stringstream &out) const override
    {
        // TODO
    }
};

/**
 * A Frequent Item metric class which knows how to render its output into a table of top N
 *
 * NOTE: intentionally _not_ thread safe; it should be protected by a mutex
 */
template <typename T>
class TopN final : public Metric
{
public:
    //
    // https://datasketches.github.io/docs/Frequency/FrequentItemsErrorTable.html
    //
    // we need to size for stream length of (essentially) pps within MetricsMgr::PERIOD_SEC
    // at close to ~1 mil PPS (5.6E+07 per 60s) we can hit being off by ~24000 at max map size of 8192
    // this number also affects memory usage, by limiting the number of objects tracked
    // e.g. up to MAX_FI_MAP_SIZE strings (ints, etc) may be stored per sketch
    // note that the actual storage space for the strings is on the heap and not counted here, though.
    const uint8_t START_FI_MAP_SIZE = 7; // 2^7 = 128
    const uint8_t MAX_FI_MAP_SIZE = 13;  // 2^13 = 8192

private:
    datasketches::frequent_items_sketch<T> _fi;
    size_t _top_count = 10;

public:
    TopN(std::initializer_list<std::string> names, std::string desc)
        : Metric(names, std::move(desc))
        , _fi(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
    {
    }

    void update(const T &value)
    {
        _fi.update(value);
    }

    void update(T &&value)
    {
        _fi.update(value);
    }

    void merge(const TopN &other)
    {
        _fi.merge(other._fi);
    }

    /**
     * to_json which takes a formater to format the "name"
     * @param j json object
     * @param formatter std::function which takes a T as input (the type store it in top table) it needs to return a std::string
     */
    void to_json(json &j, std::function<std::string(const T &)> formatter) const
    {
        auto section = json::array();
        auto items = _fi.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(_top_count, items.size()); i++) {
            section[i]["name"] = formatter(items[i].get_item());
            section[i]["estimate"] = items[i].get_estimate();
        }
        name_json_assign(j, section);
    }

    // Metric
    void to_json(json &j) const override
    {
        auto section = json::array();
        auto items = _fi.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(_top_count, items.size()); i++) {
            section[i]["name"] = items[i].get_item();
            section[i]["estimate"] = items[i].get_estimate();
        }
        name_json_assign(j, section);
    }

    void to_prometheus(std::stringstream &out) const override
    {
    }
};

/**
 * A Cardinality metric class which knows how to render its output
 *
 * NOTE: intentionally _not_ thread safe; it should be protected by a mutex
 */
class Cardinality final : public Metric
{
    datasketches::cpc_sketch _set;

public:
    Cardinality(std::initializer_list<std::string> names, std::string desc)
        : Metric(names, std::move(desc))
    {
    }

    template <typename T>
    void update(const T &value)
    {
        _set.update(value);
    }

    template <typename T>
    void update(T &&value)
    {
        _set.update(value);
    }

    void update(const void *value, int size)
    {
        _set.update(value, size);
    }

    void merge(const Cardinality &other);

    // Metric
    void to_json(json &j) const override;
    void to_prometheus(std::stringstream &out) const override;
};

/**
 * A Rate metric class which knows how to render its output
 * NOTE: this class _is_ thread safe, it _does not_ need an additional mutex
 */
class Rate final : public Metric
{
    std::atomic_uint64_t _counter;
    std::atomic_uint64_t _rate;
    mutable std::shared_mutex _sketch_mutex;
    datasketches::kll_sketch<int_fast32_t> _quantile;

    std::shared_ptr<timer::interval_handle> _timer_handle;

    void _start_timer()
    {
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

public:
    Rate(std::initializer_list<std::string> names, std::string desc)
        : Metric(names, std::move(desc))
        , _counter(0)
        , _rate(0)
        , _quantile()
    {
        _start_timer();
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
    void to_json(json &j) const override;
    void to_prometheus(std::stringstream &out) const override;
};

}