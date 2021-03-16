/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <timer.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <kll_sketch.hpp>
#pragma GCC diagnostic pop
#include <atomic>
#include <deque>
#include <exception>
#include <nlohmann/json.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#include <randutils.hpp>
#pragma GCC diagnostic pop
#include <shared_mutex>
#include <sstream>
#include <sys/time.h>
#include <unordered_map>
namespace visor {

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

using namespace std::chrono;

class Rate
{
public:
    typedef datasketches::kll_sketch<long> QuantileType;

private:
    std::atomic_uint64_t _counter;
    std::atomic_uint64_t _rate;
    mutable std::shared_mutex _sketch_mutex;
    QuantileType _quantile;

    std::shared_ptr<timer::interval_handle> _timer_handle;
    high_resolution_clock::time_point _last_ts;

public:
    Rate()
        : _counter(0)
        , _rate(0.0)
        , _quantile()
    {
        _quantile = QuantileType();
        _last_ts = high_resolution_clock::now();
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
        _rate.store(0);
        _counter.store(0);
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
        // the live rate to simply copied if non zero
        if (other._rate != 0) {
            _rate.store(other._rate, std::memory_order_relaxed);
        }
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

    timespec _start_tstamp;
    timespec _end_tstamp;
    uint _period_length = 0;
    bool _read_only = false;

protected:
    // merge the metrics of the specialized metric bucket
    virtual void specialized_merge(const AbstractMetricsBucket &other) = 0;

    // should be thread safe
    // can be used to set any bucket metrics to read only, e.g. cancel Rate metrics
    virtual void on_set_read_only(){};

public:
    AbstractMetricsBucket()
        : _rate_events()
        , _start_tstamp{0, 0}
        , _end_tstamp{0, 0}
    {
        timespec_get(&_start_tstamp, TIME_UTC);
    }

    virtual ~AbstractMetricsBucket() = default;

    timespec start_tstamp() const
    {
        std::shared_lock r_lock(_base_mutex);
        return _start_tstamp;
    }

    timespec end_tstamp() const
    {
        std::shared_lock r_lock(_base_mutex);
        return _end_tstamp;
    }

    uint period_length() const
    {
        std::shared_lock r_lock(_base_mutex);
        if (_read_only) {
            return _period_length;
        }
        timespec now;
        timespec_get(&now, TIME_UTC);
        return now.tv_sec - _start_tstamp.tv_sec;
    }

    void set_start_tstamp(timespec stamp)
    {
        std::unique_lock w_lock(_base_mutex);
        _start_tstamp = stamp;
    }

    bool read_only() const
    {
        std::shared_lock r_lock(_base_mutex);
        return _read_only;
    }

    void set_read_only(timespec stamp)
    {
        {
            std::unique_lock w_lock(_base_mutex);
            _end_tstamp = stamp;
            _period_length = _end_tstamp.tv_sec - _start_tstamp.tv_sec;
            _read_only = true;
        }
        _rate_events.cancel();
        on_set_read_only();
    }

    auto event_data() const
    {
        std::shared_lock lock(_base_mutex);
        struct eventData {
            uint64_t num_events;
            uint64_t num_samples;
            const Rate *event_rate;
        };
        return eventData{_num_events, _num_samples, &_rate_events};
    }

    void merge(const AbstractMetricsBucket &other)
    {
        {
            std::shared_lock r_lock(other._base_mutex);
            std::unique_lock w_lock(_base_mutex);
            _num_events += other._num_events;
            _num_samples += other._num_samples;
            _period_length += other.period_length();
            if (other._start_tstamp.tv_sec < _start_tstamp.tv_sec) {
                _start_tstamp.tv_sec = other._start_tstamp.tv_sec;
            }
            if (other._end_tstamp.tv_sec > _end_tstamp.tv_sec) {
                _end_tstamp.tv_sec = other._end_tstamp.tv_sec;
            }
            _read_only = true;
            _rate_events.merge(other._rate_events);
        }
        specialized_merge(other);
    }

    void new_event(bool deep)
    {
        // note, currently not enforcing _read_only
        ++_rate_events;
        std::unique_lock lock(_base_mutex);
        _num_events++;
        if (deep) {
            _num_samples++;
        }
    }

    virtual void to_json(json &j) const = 0;
    virtual void to_prometheus(std::stringstream &out, const std::string &key) const = 0;
};

template <typename MetricsBucketClass>
class AbstractMetricsManager
{
    static_assert(std::is_base_of<AbstractMetricsBucket, MetricsBucketClass>::value, "MetricsBucketClass must inherit from AbstractMetricsBucket");

private:
    // this protects changes to the bucket container, _not_ changes to the bucket itself
    mutable std::shared_mutex _bucket_mutex;
    std::deque<std::unique_ptr<MetricsBucketClass>> _metric_buckets;

    mutable std::shared_mutex _base_mutex;

    /**
     * the total number of periods we will maintain in the window
     */
    uint _num_periods;

    /**
     * sampling
     */
    randutils::default_rng _rng;
    uint _deep_sample_rate;

protected:
    std::atomic_bool _deep_sampling_now; // atomic so we can reference without mutex

private:
    /**
     * window maintenance
     */
    timespec _last_shift_tstamp;
    timespec _next_shift_tstamp;

    std::shared_ptr<timer::interval_handle> _flush_timer_handle;

    /**
     * simple cache for json results
     */
    mutable std::unordered_map<uint, std::pair<std::chrono::high_resolution_clock::time_point, json>> _mergeResultCache;

    /**
     * manage the time window
     * @param stamp time stamp of the event
     */
    void _period_shift(timespec stamp)
    {
        // ensure access to the buckets is locked while we period shift
        std::unique_lock wl(_bucket_mutex);
        std::unique_ptr<MetricsBucketClass> expiring_bucket;
        // this changes the live bucket
        _metric_buckets.emplace_front(std::make_unique<MetricsBucketClass>());
        _metric_buckets[0]->set_start_tstamp(stamp);
        // notify second most recent bucket that it is now read only, save end time
        _metric_buckets[1]->set_read_only(stamp);
        // if we're at our period history length max, pop the oldest
        if (_metric_buckets.size() > _num_periods) {
            // before popping, take ownership of the bucket we are expiring so that it can be examined by the period shift callback handler
            expiring_bucket = std::move(_metric_buckets.back());
            _metric_buckets.pop_back();
        }
        // unlock bucket lock as fast as possible, in particular before period shift callback
        wl.unlock();
        std::unique_lock wlb(_base_mutex);
        _last_shift_tstamp.tv_sec = stamp.tv_sec;
        _next_shift_tstamp.tv_sec = stamp.tv_sec + AbstractMetricsManager::PERIOD_SEC;
        wlb.unlock();
        on_period_shift(stamp, (expiring_bucket) ? expiring_bucket.get() : nullptr);
        // expiring bucket will destruct here if it exists
    }

public:
    static const uint PERIOD_SEC = 60;
    static const uint MERGE_CACHE_TTL_MS = 1000;

protected:

    /**
     * the "base" event method that should be called on every event before specialized event functionality. sampling will be
     * chosen, and the time window will be maintained
     *
     * @param stamp time stamp of the event
     */
    void new_event(timespec stamp)
    {
        // CRITICAL EVENT PATH
        _deep_sampling_now.store(true, std::memory_order_relaxed);
        if (_deep_sample_rate != 100) {
            _deep_sampling_now.store((_rng.uniform(0U, 100U) <= _deep_sample_rate), std::memory_order_relaxed);
        }
        std::shared_lock rlb(_base_mutex);
        bool will_shift = _num_periods > 1 && stamp.tv_sec >= _next_shift_tstamp.tv_sec;
        rlb.unlock();
        if (will_shift) {
            _period_shift(stamp);
        }
        std::shared_lock rl(_bucket_mutex);
        // bucket base event
        _metric_buckets[0]->new_event(_deep_sampling_now);
    }

    /**
     * call back when the time window period shift
     *
     * @param stamp if the base event included a time stamp, it will be passed along here, otherwise "now"
     * @param expiring_bucket pointer to bucket that is expiring, or nullptr if there was none (since shift may occur that does not expire a bucket)
     */
    virtual void on_period_shift([[maybe_unused]] timespec stamp, [[maybe_unused]] const MetricsBucketClass *maybe_expiring_bucket)
    {
    }

public:
    AbstractMetricsManager(uint periods, int deepSampleRate)
        : _metric_buckets{}
        , _num_periods{periods}
        , _deep_sample_rate(deepSampleRate)
        , _deep_sampling_now{true}
        , _last_shift_tstamp{0, 0}
        , _next_shift_tstamp{0, 0}
    {
        if (_deep_sample_rate > 100) {
            _deep_sample_rate = 100;
        }
        if (_deep_sample_rate < 1) {
            _deep_sample_rate = 1;
        }

        _num_periods = std::min(_num_periods, 10U);
        _num_periods = std::max(_num_periods, 1U);
        timespec_get(&_last_shift_tstamp, TIME_UTC);
        _next_shift_tstamp = _last_shift_tstamp;
        _next_shift_tstamp.tv_sec += AbstractMetricsManager::PERIOD_SEC;

        _metric_buckets.emplace_front(std::make_unique<MetricsBucketClass>());

        // the normal time window maintenance period shifting is driven by time stamps in new_event
        // but if there is are no events for more than a period, we need to flush manually to maintain
        // a proper time window
        static timer timer_thread{100ms};
        _flush_timer_handle = timer_thread.set_interval(60s, [this] {
            timespec stamp;
            timespec_get(&stamp, TIME_UTC);
            std::shared_lock rlb(_base_mutex);
            bool will_shift = _num_periods > 1 && stamp.tv_sec >= _next_shift_tstamp.tv_sec;
            rlb.unlock();
            if (will_shift) {
                _period_shift(stamp);
            }
        });
    }

    uint num_periods() const
    {
        std::shared_lock rl(_base_mutex);
        return _num_periods;
    }

    auto current_periods() const
    {
        std::shared_lock rl(_bucket_mutex);
        return _metric_buckets.size();
    }

    uint deep_sample_rate() const
    {
        std::shared_lock rl(_base_mutex);
        return _deep_sample_rate;
    }

    auto start_tstamp() const
    {
        std::shared_lock rl(_bucket_mutex);
        return _metric_buckets.front()->start_tstamp();
    }

    auto end_tstamp() const
    {
        std::shared_lock rl(_bucket_mutex);
        return _metric_buckets.back()->end_tstamp();
    }

    void set_start_tstamp(timespec stamp)
    {
        std::unique_lock wl(_base_mutex);
        // with prerecorded data with a time stamp in the past, we do not use the flush thread
        _flush_timer_handle->cancel();
        _last_shift_tstamp = stamp;
        _next_shift_tstamp.tv_sec = stamp.tv_sec + AbstractMetricsManager::PERIOD_SEC;
        wl.unlock();
        std::shared_lock rl(_bucket_mutex);
        _metric_buckets.front()->set_start_tstamp(stamp);
    }

    void set_end_tstamp(timespec stamp)
    {
        std::shared_lock rl(_bucket_mutex);
        _metric_buckets.front()->set_read_only(stamp);
    }

    const MetricsBucketClass *bucket(uint64_t period) const
    {
        std::shared_lock rl(_bucket_mutex);
        // bounds checked
        return _metric_buckets.at(period).get();
    }

    MetricsBucketClass *live_bucket()
    {
        // CRITICAL PATH
        std::shared_lock rl(_bucket_mutex);
        // NOT bounds checked
        return _metric_buckets[0].get();
    }

    void window_single_json(json &j, const std::string &key, uint64_t period = 0) const
    {
        std::shared_lock rl(_base_mutex);
        std::shared_lock rbl(_bucket_mutex);

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

        j[period_str][key]["period"]["start_ts"] = _metric_buckets.at(period)->start_tstamp().tv_sec;
        j[period_str][key]["period"]["length"] = _metric_buckets.at(period)->period_length();

        _metric_buckets.at(period)->to_json(j[period_str][key]);
    }

    void window_single_prometheus(std::stringstream &out, const std::string &key, uint64_t period = 0) const
    {
        std::shared_lock rl(_base_mutex);
        std::shared_lock rbl(_bucket_mutex);

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

        _metric_buckets.at(period)->to_prometheus(out, key);
    }

    void window_merged_json(json &j, const std::string &key, uint64_t period) const
    {
        std::shared_lock rl(_base_mutex);
        std::shared_lock rbl(_bucket_mutex);

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

        MetricsBucketClass merged;

        auto p = period;
        for (auto &m : _metric_buckets) {
            if (p-- == 0) {
                break;
            }
            merged.merge(*m);
        }

        std::string period_str = std::to_string(period) + "m";

        j[period_str][key]["period"]["start_ts"] = merged.start_tstamp().tv_sec;
        j[period_str][key]["period"]["length"] = merged.period_length();

        merged.to_json(j[period_str][key]);

        _mergeResultCache[period] = std::pair<std::chrono::high_resolution_clock::time_point, json>(std::chrono::high_resolution_clock::now(), j);
    }
};

}
