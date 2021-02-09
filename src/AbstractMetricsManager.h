#ifndef VIZERD_ABSTRACTMETRICSMANAGER_H
#define VIZERD_ABSTRACTMETRICSMANAGER_H

#include "timer.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <datasketches/kll/kll_sketch.hpp>
#pragma GCC diagnostic pop
#include <atomic>
#include <deque>
#include <exception>
#include <json/json.hpp>
#include <rng/randutils.hpp>
#include <shared_mutex>
#include <sstream>
#include <sys/time.h>
#include <unordered_map>

namespace vizer {

using json = nlohmann::json;

class PeriodException : public std::runtime_error
{
public:
    PeriodException(const char *msg)
        : std::runtime_error(msg)
    {
    }
    PeriodException(const std::string &msg)
        : std::runtime_error(msg)
    {
    }
};

class Rate
{
public:
    typedef datasketches::kll_sketch<long> QuantileType;

private:
    std::atomic_uint64_t _counter;
    std::atomic_uint64_t _rate;
    mutable std::shared_mutex _sketch_mutex;
    QuantileType _quantile;
    std::unique_ptr<Timer> _timer;

public:
    Rate()
        : _counter(0)
        , _rate(0.0)
        , _quantile()
    {
        _quantile = QuantileType();
        _timer = std::make_unique<Timer>([this] {
            _rate.store(_counter.exchange(0));
            // lock mutex for write
            std::unique_lock lock(_sketch_mutex);
            // TODO OPTIMIZE use a high res timer to track Timer calls, to ensure per sec calculation
            // don't rely on thread sleep timing
            _quantile.update(_rate);
        },
            Timer::Interval(1000), false);
        _timer->start();
    }

    ~Rate()
    {
        _timer->stop();
    }

    Rate &operator++()
    {
        inc_counter();
        return *this;
    }

    void inc_counter()
    {
        _counter.fetch_add(1, std::memory_order_relaxed);
    }

    uint64_t counter() const
    {
        return _counter;
    }

    uint64_t rate() const
    {
        return _rate;
    }

    auto quantile_get_rlocked() const
    {
        std::shared_lock lock(_sketch_mutex);
        struct retVals {
            const QuantileType *quantile;
            std::shared_lock<std::shared_mutex> lock;
        };
        return retVals{&_quantile, std::move(lock)};
    }

    void merge(const Rate &other)
    {
        auto [o_quantile, o_lock] = other.quantile_get_rlocked();
        std::unique_lock w_lock(_sketch_mutex);
        _quantile.merge(*o_quantile);
    }
};

/**
 * This class should be specialized to contain metrics and sketches specific to this handler
 * It *MUST* be thread safe, and should expect mostly writes.
 */
class AbstractMetricsBucket
{
private:
    mutable std::shared_mutex _base_mutex;
    uint64_t _num_samples = 0;
    uint64_t _num_events = 0;

    Rate _rate_events;

    timeval _bucketTS;

protected:
    virtual void specialized_merge(const AbstractMetricsBucket &other) = 0;

public:
    AbstractMetricsBucket()
        : _rate_events()
    {
        gettimeofday(&_bucketTS, nullptr);
    }
    virtual ~AbstractMetricsBucket()
    {
    }

    timeval getTS() const
    {
        return _bucketTS;
    }

    virtual void to_json(json &j) const = 0;

    auto event_data() const
    {
        std::shared_lock lock(_base_mutex);
        struct eventData {
            uint64_t num_events;
            uint64_t num_samples;
        };
        return eventData{_num_events, _num_samples};
    }

    void merge(const AbstractMetricsBucket &other)
    {
        {
            std::shared_lock r_lock(other._base_mutex);
            std::unique_lock w_lock(_base_mutex);
            _num_events += other._num_events;
            _num_samples += other._num_samples;
        }
        specialized_merge(other);
    }

    void new_event(bool deep)
    {
        ++_rate_events;
        std::unique_lock lock(_base_mutex);
        _num_events++;
        if (deep) {
            _num_samples++;
        }
    }
};

template <class MetricsBucketClass>
class AbstractMetricsManager
{
    static_assert(std::is_base_of<AbstractMetricsBucket, MetricsBucketClass>::value, "MetricsBucketClass must inherit from AbstractMetricsBucket");

protected:
    std::deque<std::unique_ptr<MetricsBucketClass>> _metric_buckets;
    uint _num_periods;
    timespec _last_shift_ts;
    std::chrono::system_clock::time_point _start_time;

    randutils::default_rng _rng;
    uint _deep_sample_rate;
    bool _deep_sampling_now;

    mutable std::unordered_map<uint, std::pair<std::chrono::high_resolution_clock::time_point, json>> _mergeResultCache;

    void new_event(timespec stamp)
    {
        // at each new event, we determine if we are sampling, to limit collection of more detailed (expensive) statistics
        _deep_sampling_now = true;
        if (_deep_sample_rate != 100) {
            _deep_sampling_now = (_rng.uniform(0U, 100U) <= _deep_sample_rate);
        }
        if (_num_periods > 1 && stamp.tv_sec - _last_shift_ts.tv_sec > AbstractMetricsManager::PERIOD_SEC) {
            _metric_buckets.emplace_back(std::make_unique<MetricsBucketClass>());
            if (_metric_buckets.size() > _num_periods) {
                // if we're at our period history length, pop the oldest
                on_period_evict(_metric_buckets.front().get(), stamp);
                // importantly, this frees memory from bucket at end of time window
                _metric_buckets.pop_front();
            }
            _last_shift_ts.tv_sec = stamp.tv_sec;
            on_period_shift(stamp);
        }
        _metric_buckets.back()->new_event(_deep_sampling_now);
    }

    virtual void on_period_shift([[maybe_unused]] timespec stamp)
    {
    }

    virtual void on_period_evict([[maybe_unused]] const MetricsBucketClass *bucket, [[maybe_unused]] timespec stamp)
    {
    }

public:
    static const uint PERIOD_SEC = 60;
    static const uint MERGE_CACHE_TTL_MS = 1000;

    AbstractMetricsManager(uint periods, int deepSampleRate)
        : _metric_buckets()
        , _num_periods(periods)
        , _last_shift_ts()
        , _start_time()
        , _deep_sample_rate(deepSampleRate)
        , _deep_sampling_now(true)
    {
        if (_deep_sample_rate > 100) {
            _deep_sample_rate = 100;
        }
        if (_deep_sample_rate < 0) {
            _deep_sample_rate = 1;
        }
        _num_periods = std::min(_num_periods, 10U);
        _num_periods = std::max(_num_periods, 1U);
        _metric_buckets.emplace_back(std::make_unique<MetricsBucketClass>());
        timespec_get(&_last_shift_ts, TIME_UTC);
        _start_time = std::chrono::system_clock::now();
    }

    uint num_periods() const
    {
        return _num_periods;
    }

    auto current_periods() const
    {
        return _metric_buckets.size();
    }

    uint deep_sample_rate() const
    {
        return _deep_sample_rate;
    }

    auto start_time() const
    {
        return _start_time;
    }

    void set_initial_tstamp(timespec stamp)
    {
        _last_shift_ts = stamp;
    }

    const MetricsBucketClass *bucket(uint64_t period) const
    {

        if (period >= _num_periods) {
            std::stringstream err;
            err << "invalid metrics period, specify [0, " << _num_periods - 1 << "]";
            throw PeriodException(err.str());
        }
        if (period >= _metric_buckets.size()) {
            std::stringstream err;
            err << "requested metrics period has not yet accumulated, current range is [0, " << _metric_buckets.size() - 1 << "]";
            throw PeriodException(err.str());
        }

        return _metric_buckets[period].get();
    }

    void to_json_single(json &j, const std::string &key, uint64_t period = 0) const
    {

        if (period >= _num_periods) {
            std::stringstream err;
            err << "invalid metrics period, specify [0, " << _num_periods - 1 << "]";
            throw PeriodException(err.str());
        }
        if (period >= _metric_buckets.size()) {
            std::stringstream err;
            err << "requested metrics period has not yet accumulated, current range is [0, " << _metric_buckets.size() - 1 << "]";
            throw PeriodException(err.str());
        }

        std::string period_str = "1m";

        auto period_length = 0;
        if (period == 0) {
            timeval now_ts;
            gettimeofday(&now_ts, nullptr);
            period_length = now_ts.tv_sec - _metric_buckets[period]->getTS().tv_sec;
        } else {
            period_length = AbstractMetricsManager::PERIOD_SEC;
        }

        j[period_str][key]["period"]["start_ts"] = _metric_buckets[period]->getTS().tv_sec;
        j[period_str][key]["period"]["length"] = period_length;

        _metric_buckets[period]->to_json(j[period_str][key]);
    }

    void to_json_merged(json &j, const std::string &key, uint64_t period) const
    {

        if (period <= 1 || period > _num_periods) {
            std::stringstream err;
            err << "invalid metrics period, specify [2, " << _num_periods << "]";
            throw PeriodException(err.str());
        }

        auto cached = _mergeResultCache.find(period);
        if (cached != _mergeResultCache.end()) {
            // cached results, make sure still valid
            auto t_diff = std::chrono::high_resolution_clock::now() - cached->second.first;
            if (std::chrono::duration_cast<std::chrono::milliseconds>(t_diff).count() < MERGE_CACHE_TTL_MS) {
                j = cached->second.second;
            } else {
                // expire
                _mergeResultCache.erase(period);
            }
        }

        auto period_length = 0;
        MetricsBucketClass merged;

        auto p = period;
        for (auto &m : _metric_buckets) {
            if (p-- == 0) {
                break;
            }
            if (m == _metric_buckets.back()) {
                timeval now_ts;
                gettimeofday(&now_ts, nullptr);
                period_length += now_ts.tv_sec - m->getTS().tv_sec;
            } else {
                period_length += AbstractMetricsManager::PERIOD_SEC;
            }
            merged.merge(*m);
        }

        std::string period_str = std::to_string(period) + "m";

        auto oldest_ts = _metric_buckets.front()->getTS();
        j[period_str][key]["period"]["start_ts"] = oldest_ts.tv_sec;
        j[period_str][key]["period"]["length"] = period_length;

        merged.to_json(j[period_str][key]);

        _mergeResultCache[period] = std::pair<std::chrono::high_resolution_clock::time_point, json>(std::chrono::high_resolution_clock::now(), j);
    }
};

}

#endif //VIZERD_ABSTRACTMETRICSMANAGER_H
