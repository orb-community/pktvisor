#pragma once

#include <DnsLayer.h>
#include <ProtocolType.h>
#include <IpUtils.h>
#include <datasketches/cpc/cpc_sketch.hpp>
#include <datasketches/fi/frequent_items_sketch.hpp>
#include <datasketches/kll/kll_sketch.hpp>
#include <json/json.hpp>
#include "config.h"

#ifdef MMDB_ENABLE
#include "geoip.h"
#endif

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <deque>
#include <shared_mutex>
#include <string>
#include <atomic>

#include "pktvisor.h"
#include "querypairmgr.h"
#include "timer.h"

namespace pktvisor {

using hr_clock = std::chrono::high_resolution_clock;

class MetricsMgr;

class Rate
{
public:
    typedef datasketches::kll_sketch<long> QuantileType;
    typedef std::vector<long, std::allocator<long>> QuantileResultType;

private:
    std::atomic_uint64_t _counter;
    std::atomic_uint64_t _curRate;
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
            _curRate.store(_counter.exchange(0));
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

    void resetQuantile() {
        // lock mutex for write
        std::unique_lock lock(_sketchMutex);
        _quantile = std::make_unique<QuantileType>();
    }

};

struct IPv4Hash {
    size_t operator()(uint32_t k) {
        return pcpp::fnv_hash((uint8_t*)&k, sizeof(k));
    }
};

struct Sketches {

    //
    // https://datasketches.github.io/docs/Frequency/FrequentItemsErrorTable.html
    //
    // we need to size for stream length of (essentially) pps within MetricsMgr::PERIOD_SEC
    // at close to ~1 mil PPS (5.6E+07 per 60s) we can hit being off by ~24000 at max map size of 8192
    // this number also affects memory usage, by limiting the number of objects tracked
    // e.g. up to MAX_FI_MAP_SIZE strings (ints, etc) may be stored per sketch
    // note that the actual storage space for the strings is on the heap and not counted here, though.
    const uint8_t MIN_FI_MAP_SIZE = 7;  // 2^7 = 128
    const uint8_t MAX_FI_MAP_SIZE = 13; // 2^13 = 8192

    datasketches::kll_sketch<double> _dnsXactFromTimeMs;
    datasketches::kll_sketch<double> _dnsXactToTimeMs;

    datasketches::cpc_sketch _net_srcIPCard;
    datasketches::cpc_sketch _net_dstIPCard;
    datasketches::cpc_sketch _dns_qnameCard;

    datasketches::frequent_items_sketch<std::string> _dns_topQname2;
    datasketches::frequent_items_sketch<std::string> _dns_topQname3;
    datasketches::frequent_items_sketch<std::string> _dns_topNX;
    datasketches::frequent_items_sketch<std::string> _dns_topREFUSED;
    datasketches::frequent_items_sketch<std::string> _dns_topSRVFAIL;
    datasketches::frequent_items_sketch<uint16_t> _dns_topUDPPort;
    datasketches::frequent_items_sketch<uint32_t, IPv4Hash> _net_topIPv4;
    datasketches::frequent_items_sketch<std::string> _net_topIPv6; // TODO not very efficient, should switch to 16 byte uint
    datasketches::frequent_items_sketch<uint16_t> _dns_topQType;
    datasketches::frequent_items_sketch<uint16_t> _dns_topRCode;
    datasketches::frequent_items_sketch<std::string> _dns_slowXactIn;
    datasketches::frequent_items_sketch<std::string> _dns_slowXactOut;
    datasketches::frequent_items_sketch<std::string> _net_topGeoLoc;
    datasketches::frequent_items_sketch<std::string> _net_topASN;
    Sketches()
        : _dnsXactFromTimeMs()
        , _dnsXactToTimeMs()
        , _net_srcIPCard()
        , _net_dstIPCard()
        , _dns_qnameCard()
        , _dns_topQname2(MIN_FI_MAP_SIZE, MAX_FI_MAP_SIZE)
        , _dns_topQname3(MIN_FI_MAP_SIZE, MAX_FI_MAP_SIZE)
        , _dns_topNX(MIN_FI_MAP_SIZE, MAX_FI_MAP_SIZE)
        , _dns_topREFUSED(MIN_FI_MAP_SIZE, MAX_FI_MAP_SIZE)
        , _dns_topSRVFAIL(MIN_FI_MAP_SIZE, MAX_FI_MAP_SIZE)
        , _dns_topUDPPort(MIN_FI_MAP_SIZE, MAX_FI_MAP_SIZE)
        , _net_topIPv4(MIN_FI_MAP_SIZE, MAX_FI_MAP_SIZE)
        , _net_topIPv6(MIN_FI_MAP_SIZE, MAX_FI_MAP_SIZE)
        , _dns_topQType(MIN_FI_MAP_SIZE, MAX_FI_MAP_SIZE)
        , _dns_topRCode(MIN_FI_MAP_SIZE, MAX_FI_MAP_SIZE)
        , _dns_slowXactIn(MIN_FI_MAP_SIZE, MAX_FI_MAP_SIZE)
        , _dns_slowXactOut(MIN_FI_MAP_SIZE, MAX_FI_MAP_SIZE)
        , _net_topGeoLoc(MIN_FI_MAP_SIZE, MAX_FI_MAP_SIZE)
        , _net_topASN(MIN_FI_MAP_SIZE, MAX_FI_MAP_SIZE)
    {
    }
};

struct RateSketches {
    Rate::QuantileType net_rateIn;
    Rate::QuantileType net_rateOut;
};

struct InstantRateMetrics {
    Rate _rate_in;
    Rate _rate_out;
    void resetQuantiles() {
        _rate_in.resetQuantile();
        _rate_out.resetQuantile();
    }
};

class Metrics
{

    // always the first second of the bucket, i.e. this bucket contains from this timestamp to timestamp + MetricsMgr::PERIOD_SEC
    timeval _bucketTS;

    std::atomic_uint64_t _numPackets = 0;
    std::atomic_uint64_t _numPackets_UDP = 0;
    std::atomic_uint64_t _numPackets_TCP = 0;
    std::atomic_uint64_t _numPackets_IPv6 = 0;
    std::atomic_uint64_t _numPackets_in = 0;
    std::atomic_uint64_t _numPackets_out = 0;

    std::atomic_uint64_t _DNS_total = 0;
    std::atomic_uint64_t _DNS_xacts_total = 0;
    std::atomic_uint64_t _DNS_xacts_in = 0;
    std::atomic_uint64_t _DNS_xacts_out = 0;
    std::atomic_uint64_t _DNS_queries = 0;
    std::atomic_uint64_t _DNS_replies = 0;
    std::atomic_uint64_t _DNS_TCP = 0;
    std::atomic_uint64_t _DNS_IPv6 = 0;
    std::atomic_uint64_t _DNS_NX = 0;
    std::atomic_uint64_t _DNS_REFUSED = 0;
    std::atomic_uint64_t _DNS_SRVFAIL = 0;
    std::atomic_uint64_t _DNS_NOERROR = 0;

    // TODO don't need unique_ptr anymore?
    std::unique_ptr<Sketches> _sketches;
    std::shared_mutex _sketchMutex;

    RateSketches _rateSketches;
    std::shared_mutex _rateSketchMutex;

public:
    Metrics();

    void merge(Metrics &other);

    timeval getTS() const
    {
        return _bucketTS;
    }

    void assignRateSketches(const std::shared_ptr<InstantRateMetrics>);
    void toJSON(nlohmann::json &j, const std::string &key);

    void newPacket(MetricsMgr &mmgr, const pcpp::Packet &packet, pcpp::ProtocolType l3, pcpp::ProtocolType l4, Direction dir);
    void newDNSPacket(pcpp::DnsLayer *dns, Direction dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4);
    void newDNSXact(pcpp::DnsLayer *dns, Direction dir, DnsTransaction xact);
};

class MetricsMgr
{
    std::deque<std::unique_ptr<Metrics>> _metrics;
    uint _numPeriods;
    timeval _lastShiftTS;
    long _openDnsTransactionCount;
    bool _singleSummaryMode;
    std::chrono::system_clock::time_point _startTime;

    // instantaneous rate metrics
    std::shared_ptr<InstantRateMetrics> _instantRates;

    void _periodShift();

#ifdef MMDB_ENABLE
    std::unique_ptr<GeoDB> _geoCityDB;
    std::unique_ptr<GeoDB> _geoASNDB;
#endif

public:
    static const uint PERIOD_SEC = 60;

    MetricsMgr(bool singleSummaryMode, uint periods = 5)
        : _metrics()
        , _numPeriods(periods)
        , _lastShiftTS()
        , _openDnsTransactionCount(0)
        , _singleSummaryMode(singleSummaryMode)
        , _startTime()
        , _instantRates()
    {
        if (singleSummaryMode) {
            _numPeriods = 1;
        }
        _instantRates = std::make_shared<InstantRateMetrics>();
        _numPeriods = std::min(_numPeriods, 10U);
        _numPeriods = std::max(_numPeriods, 2U);
        _metrics.emplace_back(std::make_unique<Metrics>());
        _lastShiftTS.tv_sec = 0;
        _lastShiftTS.tv_usec = 0;
        _startTime = std::chrono::system_clock::now();
    }

    void setInitialShiftTS();
    void setInitialShiftTS(const pcpp::Packet &packet);

    bool haveGeoCity() {
#ifdef MMDB_ENABLE
        return true;
#else
        return false;
#endif
    }

    void setGeoCityDB(const std::string& name) {
#ifdef MMDB_ENABLE
        _geoCityDB = std::make_unique<GeoDB>(name);
#else
        throw std::logic_error("setGeoCityDB called but is lacking compile-time support");
#endif
    }

    bool haveGeoASN() {
#ifdef MMDB_ENABLE
        return true;
#else
        return false;
#endif
    }

    void setGeoASNDB(const std::string& name) {
#ifdef MMDB_ENABLE
        _geoASNDB = std::make_unique<GeoDB>(name);
#else
        throw std::logic_error("setGeoASNDB called but is lacking compile-time support");
#endif
    }

#ifdef MMDB_ENABLE
    const GeoDB* getGeoCityDB() { return _geoCityDB.get(); }
    const GeoDB* getGeoASNDB() { return _geoASNDB.get(); }
#endif

    void newPacket(const pcpp::Packet &packet, QueryResponsePairMgr &pairMgr, pcpp::ProtocolType l4, Direction dir, pcpp::ProtocolType l3);
    void newDNSPacket(pcpp::DnsLayer *dns, Direction dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4);
    void newDNSXact(pcpp::DnsLayer *dns, Direction dir, DnsTransaction xact);

    std::string getAppMetrics();
    std::string getInstantRates();
    std::string getMetrics(uint64_t period = 0);
    std::string getMetricsMerged(uint64_t period);
};

}
