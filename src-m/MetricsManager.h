#ifndef PKTVISORD_METRICSMANAGER_H
#define PKTVISORD_METRICSMANAGER_H

#include "timer.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <datasketches/kll/kll_sketch.hpp>
#pragma GCC diagnostic pop
#include <deque>
#include <json/json.hpp>
#include <rng/randutils.hpp>
#include <shared_mutex>
#include <sys/time.h>
#include <unordered_map>

using json = nlohmann::json;

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

template <class MetricsClass>
class MetricsManager;

template <class MetricsClass, class SketchesClass>
class Metrics
{

protected:
    // always the first second of the bucket, i.e. this bucket contains from this timestamp to timestamp + MetricsMgr::PERIOD_SEC
    timeval _bucketTS;
    // TODO don't need unique_ptr anymore?
    std::unique_ptr<SketchesClass> _sketches;
    std::shared_mutex _sketchMutex;

    MetricsManager<MetricsClass> &_mmgr;

public:
    Metrics(MetricsManager<MetricsClass> &mmgr)
        : _mmgr(mmgr)
    {
        gettimeofday(&_bucketTS, nullptr);

        // lock for write
        std::unique_lock lock(_sketchMutex);
        _sketches = std::make_unique<SketchesClass>();
    }
    virtual ~Metrics()
    {
    }

    //virtual void merge(MetricsClass<SketchesClass> &other) = 0;

    timeval getTS() const
    {
        return _bucketTS;
    }

    /*    void assignRateSketches(const std::shared_ptr<InstantRateMetrics>);*/
    virtual void toJSON(json &j, const std::string &key) = 0;
};

template <class MetricsClass>
class MetricsManager
{
protected:
    std::deque<std::unique_ptr<MetricsClass>> _metrics;
    uint _numPeriods;
    timespec _lastShiftTS;
    //    long _openDnsTransactionCount;
    bool _singleSummaryMode;
    std::chrono::system_clock::time_point _startTime;

    // instantaneous rate metrics
    std::shared_ptr<InstantRateMetrics> _instantRates;

    randutils::default_rng _rng;
    int _deepSampleRate;
    bool _shouldDeepSample;

    std::unordered_map<uint, std::pair<std::chrono::high_resolution_clock::time_point, std::string>> _mergeResultCache;

    void _periodShift()
    {

        // copy instant rate results into bucket before shift
        //_metrics.back()->assignRateSketches(_instantRates);
        // reset instant rate quantiles so they are accurate for next minute bucket
        //_instantRates->resetQuantiles();

        // add new bucket
        _metrics.emplace_back(std::make_unique<MetricsClass>(*this));
        if (_metrics.size() > _numPeriods) {
            // if we're at our period history length, pop the oldest
            _metrics.pop_front();
        }
    }

public:
    static const uint PERIOD_SEC = 60;
    static const uint MERGE_CACHE_TTL_MS = 1000;

    MetricsManager(bool singleSummaryMode, uint periods, int deepSampleRate)
        : _metrics()
        , _numPeriods(periods)
        , _lastShiftTS()
        //        , _openDnsTransactionCount(0)
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
        _metrics.emplace_back(std::make_unique<MetricsClass>(*this));
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

    /*
    std::string getAppMetrics();
    std::string getInstantRates();
     */

    void getMetrics(json &j, uint64_t period = 0)
    {
        if (_singleSummaryMode) {
            period = 0;
        } else {
            if (period >= _numPeriods) {
                /* TODO
                std::stringstream err;
                err << "invalid metrics period, specify [0, " << _numPeriods - 1 << "]";
                j["error"] = err.str();
                 */
            }
            if (period >= _metrics.size()) {
                /*
                std::stringstream err;
                err << "this metrics period has not yet accumulated, current range is [0, " << _metrics.size() - 1 << "]";
                j["error"] = err.str();
                 */
            }
        }

        std::string period_str = "1m";

        auto period_length = 0;
        if (period == 0) {
            timeval now_ts;
            gettimeofday(&now_ts, nullptr);
            period_length = now_ts.tv_sec - _metrics[period]->getTS().tv_sec;
        } else {
            period_length = MetricsManager::PERIOD_SEC;
        }

        j[period_str]["period"]["start_ts"] = _metrics[period]->getTS().tv_sec;
        j[period_str]["period"]["length"] = period_length;

        _metrics[period]->toJSON(j, period_str);
    }

    /*
    std::string getMetricsMerged(uint64_t period);
     */
};

}

#endif //PKTVISORD_METRICSMANAGER_H
