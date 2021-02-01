#ifndef PKTVISORD_ABSTRACTMETRICSMANAGER_H
#define PKTVISORD_ABSTRACTMETRICSMANAGER_H

#include "timer.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <datasketches/kll/kll_sketch.hpp>
#pragma GCC diagnostic pop
#include <atomic>
#include <deque>
#include <json/json.hpp>
#include <rng/randutils.hpp>
#include <shared_mutex>
#include <sys/time.h>
#include <unordered_map>

namespace pktvisor {

using json = nlohmann::json;

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
 * This class should be be specialized to contain metrics and sketches specific to this handler
 * It *MUST* be thread safe, and should expect mostly writes.
 */
class AbstractMetricsBucket
{

protected:
    // always the first second of the bucket, i.e. this bucket contains from this timestamp to timestamp + MetricsMgr::PERIOD_SEC
    timeval _bucketTS;
    mutable std::shared_mutex _mutex;

    uint64_t _numSamples = 0;
    uint64_t _numEvents = 0;

public:
    AbstractMetricsBucket()
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

    void newEvent(bool deep)
    {
        std::unique_lock w_lock(_mutex);
        _numEvents++;
        if (deep) {
            _numSamples++;
        }
    }

    /*    void assignRateSketches(const std::shared_ptr<InstantRateMetrics>);*/
    virtual void toJSON(json &j) const = 0;
    virtual void merge(const AbstractMetricsBucket &other) = 0;
};

template <class MetricsBucketClass>
class AbstractMetricsManager
{
    static_assert(std::is_base_of<AbstractMetricsBucket, MetricsBucketClass>::value, "MetricsBucketClass must inherit from AbstractMetricsBucket");

protected:
    std::deque<std::unique_ptr<MetricsBucketClass>> _metricBuckets;
    uint _numPeriods;
    timespec _lastShiftTS;
    std::chrono::system_clock::time_point _startTime;

    randutils::default_rng _rng;
    int _deepSampleRate;
    bool _shouldDeepSample;

    std::unordered_map<uint, std::pair<std::chrono::high_resolution_clock::time_point, json>> _mergeResultCache;

    void new_event(timespec stamp)
    {
        // at each new event, we determine if we are sampling, to limit collection of more detailed (expensive) statistics
        _shouldDeepSample = true;
        if (_deepSampleRate != 100) {
            _shouldDeepSample = (_rng.uniform(0, 100) <= _deepSampleRate);
        }
        if (_numPeriods > 1 && stamp.tv_sec - _lastShiftTS.tv_sec > AbstractMetricsManager::PERIOD_SEC) {
            _metricBuckets.emplace_back(std::make_unique<MetricsBucketClass>());
            if (_metricBuckets.size() > _numPeriods) {
                // if we're at our period history length, pop the oldest
                on_period_evict(_metricBuckets.front().get());
                _metricBuckets.pop_front();
            }
            _lastShiftTS.tv_sec = stamp.tv_sec;
            on_period_shift();
        }
    }

    virtual void on_period_shift()
    {
    }

    virtual void on_period_evict(const MetricsBucketClass *bucket)
    {
    }

public:
    // TODO
    static const uint PERIOD_SEC = 60;
    static const uint MERGE_CACHE_TTL_MS = 1000;

    AbstractMetricsManager(uint periods, int deepSampleRate)
        : _metricBuckets()
        , _numPeriods(periods)
        , _lastShiftTS()
        , _startTime()
        , _deepSampleRate(deepSampleRate)
        , _shouldDeepSample(true)
    {
        if (_deepSampleRate > 100) {
            _deepSampleRate = 100;
        }
        if (_deepSampleRate < 0) {
            _deepSampleRate = 1;
        }
        _numPeriods = std::min(_numPeriods, 10U);
        _numPeriods = std::max(_numPeriods, 1U);
        _metricBuckets.emplace_back(std::make_unique<MetricsBucketClass>());
        timespec_get(&_lastShiftTS, TIME_UTC);
        _startTime = std::chrono::system_clock::now();
    }

    void set_initial_tstamp(timespec stamp)
    {
        _lastShiftTS = stamp;
    }


    void toJSONSingle(json &j, uint64_t period = 0)
    {

        if (period >= _numPeriods) {
            /* TODO
                std::stringstream err;
                err << "invalid metrics period, specify [0, " << _numPeriods - 1 << "]";
                j["error"] = err.str();
                 */
            return;
        }
        if (period >= _metricBuckets.size()) {
            /*
                std::stringstream err;
                err << "this metrics period has not yet accumulated, current range is [0, " << _metricBuckets.size() - 1 << "]";
                j["error"] = err.str();
                 */
            return;
        }

        std::string period_str = "1m";

        auto period_length = 0;
        if (period == 0) {
            timeval now_ts;
            gettimeofday(&now_ts, nullptr);
            period_length = now_ts.tv_sec - _metricBuckets[period]->getTS().tv_sec;
        } else {
            period_length = AbstractMetricsManager::PERIOD_SEC;
        }

        j[period_str]["period"]["start_ts"] = _metricBuckets[period]->getTS().tv_sec;
        j[period_str]["period"]["length"] = period_length;

        _metricBuckets[period]->toJSON(j[period_str]);
    }

    void toJSONMerged(json &j, uint64_t period)
    {

        if (period <= 1 || period > _numPeriods) {
            /*            std::stringstream err;
            err << "invalid metrics period, specify [2, " << _numPeriods << "]";
            j["error"] = err.str();
            return j.dump();*/
            return;
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
        for (auto &m : _metricBuckets) {
            if (p-- == 0) {
                break;
            }
            if (m == _metricBuckets.back()) {
                timeval now_ts;
                gettimeofday(&now_ts, nullptr);
                period_length += now_ts.tv_sec - m->getTS().tv_sec;
            } else {
                period_length += AbstractMetricsManager::PERIOD_SEC;
            }
            merged.merge(*m);
        }

        std::string period_str = std::to_string(period) + "m";

        auto oldest_ts
            = _metricBuckets.front()->getTS();
        j[period_str]["period"]["start_ts"] = oldest_ts.tv_sec;
        j[period_str]["period"]["length"] = period_length;

        merged.toJSON(j[period_str]);

        _mergeResultCache[period] = std::pair<std::chrono::high_resolution_clock::time_point, json>(std::chrono::high_resolution_clock::now(), j);
    }
};

}

#endif //PKTVISORD_ABSTRACTMETRICSMANAGER_H
