#ifndef PKTVISORD_METRICSMANAGER_H
#define PKTVISORD_METRICSMANAGER_H

#include "timer.h"
#include <datasketches/kll/kll_sketch.hpp>
#include <deque>
#include <rng/randutils.hpp>
#include <shared_mutex>
#include <unordered_map>

namespace pktvisor {

class Rate
{
public:
    typedef datasketches::kll_sketch<long> QuantileType;
    typedef std::vector<long, std::allocator<long>> QuantileResultType;

private:
    uint64_t _counter;
    uint64_t _curRate;
    mutable std::shared_mutex _sketchMutex;
    std::unique_ptr<QuantileType> _quantile;
    std::unique_ptr<Timer> _timer;

public:
    Rate()
        : _counter(0)
        , _curRate(0.0)
        , _quantile()
    {
        _quantile = std::make_unique<QuantileType>();
        _timer = std::make_unique<Timer>([this] {
            // lock mutex for write
            std::unique_lock lock(_sketchMutex);
            _quantile->update(_curRate);
        },
            Timer::Interval(1000), false);
        _timer->start();
    }

    ~Rate()
    {
        _timer->stop();
    }

    void incCounter()
    {
        _counter++;
    }
    uint64_t getCounter()
    {
        return _counter;
    }

    uint64_t getRate()
    {
        return _curRate;
    }

    QuantileType getQuantileCopy() const
    {
        // lock mutex for read
        std::unique_lock lock(_sketchMutex);
        // TODO is this two copies at call site? optimize if we care
        auto q_copy = *_quantile;
        return q_copy;
    }

    QuantileResultType getQuantileResults()
    {
        // lock mutex for read
        std::shared_lock lock(_sketchMutex);
        const double fractions[4]{0.50, 0.90, 0.95, 0.99};
        return _quantile->get_quantiles(fractions, 4);
    }

    void resetQuantile()
    {
        // lock mutex for write
        std::unique_lock lock(_sketchMutex);
        _quantile = std::make_unique<QuantileType>();
    }
};

struct InstantRateMetrics {
    Rate _rate_in;
    Rate _rate_out;
    void resetQuantiles()
    {
        _rate_in.resetQuantile();
        _rate_out.resetQuantile();
    }
};

template <class Sketches>
class MetricsManager;

template <class Sketches>
class Metrics
{

    // always the first second of the bucket, i.e. this bucket contains from this timestamp to timestamp + MetricsMgr::PERIOD_SEC
    timeval _bucketTS;

    // TODO don't need unique_ptr anymore?
    std::unique_ptr<Sketches> _sketches;
    std::shared_mutex _sketchMutex;

    MetricsManager<Sketches> &_mmgr;

public:
    Metrics(MetricsManager<Sketches> &mmgr);

    void merge(Metrics &other);

    timeval getTS() const
    {
        return _bucketTS;
    }

    /*    void assignRateSketches(const std::shared_ptr<InstantRateMetrics>);
    void toJSON(nlohmann::json &j, const std::string &key);*/
};

template <class Sketches>
class MetricsManager
{
    std::deque<std::unique_ptr<Metrics<Sketches>>> _metrics;
    uint _numPeriods;
    timespec _lastShiftTS;
    long _openDnsTransactionCount;
    bool _singleSummaryMode;
    std::chrono::system_clock::time_point _startTime;

    // instantaneous rate metrics
    std::shared_ptr<InstantRateMetrics> _instantRates;

    randutils::default_rng _rng;
    int _deepSampleRate;
    bool _shouldDeepSample;

    std::unordered_map<uint, std::pair<std::chrono::high_resolution_clock::time_point, std::string>> _mergeResultCache;

    void _periodShift();

public:
    static const uint PERIOD_SEC = 60;
    static const uint MERGE_CACHE_TTL_MS = 1000;

    MetricsManager(bool singleSummaryMode, uint periods, int deepSampleRate)
        : _metrics()
        , _numPeriods(periods)
        , _lastShiftTS()
        , _openDnsTransactionCount(0)
        , _singleSummaryMode(singleSummaryMode)
        , _startTime()
        , _instantRates()
        , _deepSampleRate(deepSampleRate)
        , _shouldDeepSample(true)
    {
        if (singleSummaryMode) {
            _numPeriods = 1;
        }
        if (_deepSampleRate > 100) {
            _deepSampleRate = 100;
        }
        if (_deepSampleRate < 0) {
            _deepSampleRate = 1;
        }
        _instantRates = std::make_shared<InstantRateMetrics>();
        _numPeriods = std::min(_numPeriods, 10U);
        _numPeriods = std::max(_numPeriods, 2U);
        _metrics.emplace_back(std::make_unique<Metrics>(*this));
        _lastShiftTS.tv_sec = 0;
        _lastShiftTS.tv_nsec = 0;
        _startTime = std::chrono::system_clock::now();
    }

    bool shouldDeepSample()
    {
        return _shouldDeepSample;
    }

    void setInitialShiftTS();
    //    void setInitialShiftTS(const pcpp::Packet &packet);

    std::string getAppMetrics();
    std::string getInstantRates();
    std::string getMetrics(uint64_t period = 0);
    std::string getMetricsMerged(uint64_t period);
};

}

#endif //PKTVISORD_METRICSMANAGER_H
