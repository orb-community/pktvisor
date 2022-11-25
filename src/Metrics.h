/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once
#include <nlohmann/json.hpp>
#include <sstream>
#include <timer.hpp>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wrange-loop-analysis"
#endif
#include <cpc_sketch.hpp>
#include <frequent_items_sketch.hpp>
#include <kll_sketch.hpp>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <chrono>
#include <regex>
#include <shared_mutex>
#include <vector>

namespace visor {

using json = nlohmann::json;
using namespace std::chrono;

class Metric
{
public:
    typedef std::map<std::string, std::string> LabelMap;

    enum class Aggregate {
        DEFAULT,
        SUM,
    };

private:
    /**
     * static labels which will be applied to all metrics
     */
    static LabelMap _static_labels;

protected:
    std::vector<std::string> _name;
    std::string _desc;
    std::string _schema_key;

    void _check_names()
    {
        for (const auto &name : _name) {
            if (!std::regex_match(name, std::regex(LABEL_REGEX))) {
                throw std::runtime_error("invalid metric name: " + name);
            }
        }
        if (!std::regex_match(_schema_key, std::regex(LABEL_REGEX))) {
            throw std::runtime_error("invalid schema name: " + _schema_key);
        }
    }

public:
    inline static const std::string LABEL_REGEX = "[a-zA-Z_][a-zA-Z0-9_]*";

    Metric(std::string schema_key, std::initializer_list<std::string> names, std::string desc)
        : _name(names)
        , _desc(std::move(desc))
        , _schema_key(schema_key)
    {
        _check_names();
    }

    void set_info(std::string schema_key, std::initializer_list<std::string> names, const std::string &desc)
    {
        _name.clear();
        _name = names;
        _desc = desc;
        _schema_key = schema_key;
        _check_names();
    }

    static void add_static_label(const std::string &label, const std::string &value)
    {
        _static_labels.emplace(label, value);
    }

    void name_json_assign(json &j, const json &val) const;
    void name_json_assign(json &j, std::initializer_list<std::string> add_names, const json &val) const;

    [[nodiscard]] std::string base_name_snake() const;
    [[nodiscard]] std::string name_snake(std::initializer_list<std::string> add_names = {}, LabelMap add_labels = {}) const;

    virtual void to_json(json &j) const = 0;
    virtual void to_prometheus(std::stringstream &out, LabelMap add_labels = {}) const = 0;
};

/**
 * A Counter metric class which knows how to render its output
 * NOTE: intentionally _not_ thread safe; it should be protected by a mutex
 */
class Counter final : public Metric
{
    uint64_t _value = 0;

public:
    Counter(std::string schema_key, std::initializer_list<std::string> names, std::string desc)
        : Metric(schema_key, names, std::move(desc))
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

    void clear()
    {
        _value = 0;
    }

    // Metric
    void to_json(json &j) const override;
    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override;
};

/**
 * A Histogram metric class which knows how to render its output into buckets
 *
 * NOTE: intentionally _not_ thread safe; it should be protected by a mutex
 */
template <typename T>
class Histogram final : public Metric
{
    static_assert(std::is_integral<T>::value || std::is_floating_point<T>::value);
    T _pace;
    datasketches::kll_sketch<T> _sketch;

public:
    Histogram(std::string schema_key, std::initializer_list<std::string> names, std::string desc)
        : Metric(schema_key, names, std::move(desc))
    {
        if constexpr (std::is_integral<T>::value) {
            _pace = 1;
        } else {
            _pace = 0.0000001;
        }
    }

    void update(const T &value)
    {
        _sketch.update(value);
    }

    void update(T &&value)
    {
        _sketch.update(value);
    }

    void merge(const Histogram &other)
    {
        _sketch.merge(other._sketch);
    }

    auto get_n() const
    {
        return _sketch.get_n();
    }

    auto get_min() const
    {
        return _sketch.get_min_value();
    }

    auto get_max() const
    {
        return _sketch.get_max_value();
    }

    // Metric
    void to_json(json &j) const override
    {
        if (_sketch.is_empty()) {
            return;
        }
        std::size_t split_point_size = 1 + static_cast<std::size_t>(std::log2(_sketch.get_n())); // Sturge’s Rule
        T step = _sketch.get_max_value() / split_point_size;
        T split_point = step;
        std::unique_ptr<T[]> bins = std::make_unique<T[]>(split_point_size);
        for (std::size_t i = 0; i < split_point_size; ++i) {
            bins[i] = split_point + _pace;
            split_point += step;
            if (split_point > _sketch.get_max_value()) {
                split_point = _sketch.get_max_value();
            }
        }
        auto histogram = _sketch.get_CDF(bins.get(), split_point_size);
        for (std::size_t i = 0; i < split_point_size; ++i) {
            name_json_assign(j, {"buckets", std::to_string(bins[i] - _pace)}, histogram[i] * _sketch.get_n());
        }
        name_json_assign(j, {"buckets", "+Inf"}, histogram[split_point_size] * _sketch.get_n());
    }

    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override
    {
        if (_sketch.is_empty()) {
            return;
        }
        std::size_t split_point_size = 1 + static_cast<std::size_t>(std::log2(_sketch.get_n())); // Sturge’s Rule
        T step = _sketch.get_max_value() / split_point_size;
        T split_point = step;
        std::unique_ptr<T[]> bins = std::make_unique<T[]>(split_point_size);
        for (std::size_t i = 0; i < split_point_size; ++i) {
            bins[i] = split_point + _pace;
            split_point += step;
            if (split_point > _sketch.get_max_value()) {
                split_point = _sketch.get_max_value();
            }
        }
        auto histogram = _sketch.get_CDF(bins.get(), split_point_size);

        out << "# HELP " << base_name_snake() << ' ' << _desc << std::endl;
        out << "# TYPE " << base_name_snake() << " histogram" << std::endl;
        for (std::size_t i = 0; i < split_point_size; ++i) {
            LabelMap le(add_labels);
            le["le"] = std::to_string(bins[i] - _pace);
            out << name_snake({"bucket"}, le) << ' ' << histogram[i] * _sketch.get_n() << std::endl;
        }
        LabelMap le(add_labels);
        le["le"] = "+Inf";
        out << name_snake({"bucket"}, le) << ' ' << histogram[split_point_size] * _sketch.get_n() << std::endl;
        out << name_snake({"count"}, add_labels) << ' ' << _sketch.get_n() << std::endl;
    }
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
    std::vector<T> _quantiles_sum;

public:
    Quantile(std::string schema_key, std::initializer_list<std::string> names, std::string desc)
        : Metric(schema_key, names, std::move(desc))
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

    void merge(const Quantile &other, Aggregate agg_operator)
    {
        if (agg_operator == Aggregate::SUM && !_quantile.is_empty()) {
            if (other._quantile.is_empty()) {
                return;
            }
            const double fractions[4]{0.50, 0.90, 0.95, 0.99};
            auto other_quantiles = other._quantile.get_quantiles(fractions, 4);
            if (_quantiles_sum.empty()) {
                _quantiles_sum = _quantile.get_quantiles(fractions, 4);
            }
            for (uint8_t i = 0; i < 4; i++) {
                _quantiles_sum[i] += other_quantiles[i];
            }
        } else {
            _quantile.merge(other._quantile);
        }
    }

    auto get_n() const
    {
        return _quantile.get_n();
    }

    auto get_quantile(float p) const
    {
        return _quantile.get_quantile(p);
    }

    auto get_min() const
    {
        return _quantile.get_min_value();
    }

    auto get_max() const
    {
        return _quantile.get_max_value();
    }

    // Metric
    void to_json(json &j) const override
    {
        std::vector<T> quantiles;
        if (_quantiles_sum.empty()) {
            const double fractions[4]{0.50, 0.90, 0.95, 0.99};
            quantiles = _quantile.get_quantiles(fractions, 4);
        } else {
            quantiles = _quantiles_sum;
        }

        if (quantiles.size()) {
            name_json_assign(j, {"p50"}, quantiles[0]);
            name_json_assign(j, {"p90"}, quantiles[1]);
            name_json_assign(j, {"p95"}, quantiles[2]);
            name_json_assign(j, {"p99"}, quantiles[3]);
        }
    }

    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override
    {
        std::vector<T> quantiles;
        if (_quantiles_sum.empty()) {
            const double fractions[4]{0.50, 0.90, 0.95, 0.99};
            quantiles = _quantile.get_quantiles(fractions, 4);
        } else {
            quantiles = _quantiles_sum;
        }

        LabelMap l5(add_labels);
        l5["quantile"] = "0.5";
        LabelMap l9(add_labels);
        l9["quantile"] = "0.9";
        LabelMap l95(add_labels);
        l95["quantile"] = "0.95";
        LabelMap l99(add_labels);
        l99["quantile"] = "0.99";

        if (quantiles.size()) {
            out << "# HELP " << base_name_snake() << ' ' << _desc << std::endl;
            out << "# TYPE " << base_name_snake() << " summary" << std::endl;
            out << name_snake({}, l5) << ' ' << quantiles[0] << std::endl;
            out << name_snake({}, l9) << ' ' << quantiles[1] << std::endl;
            out << name_snake({}, l95) << ' ' << quantiles[2] << std::endl;
            out << name_snake({}, l99) << ' ' << quantiles[3] << std::endl;
            out << name_snake({"sum"}, add_labels) << ' ' << _quantile.get_max_value() << std::endl;
            out << name_snake({"count"}, add_labels) << ' ' << _quantile.get_n() << std::endl;
        }
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
    static constexpr uint64_t DEFAULT_PERCENTILE_THRESHOLD = 0;

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
    std::string _item_key;
    double _percentile_threshold = 0.0;

    uint64_t _get_threshold(const std::vector<typename datasketches::frequent_items_sketch<T>::row> &items) const
    {
        datasketches::kll_sketch<uint64_t> quantile;
        for (uint64_t i = 0; i < std::min(_top_count, items.size()); i++) {
            quantile.update(items[i].get_estimate());
        }
        if (quantile.is_empty()) {
            return 0;
        }
        return quantile.get_quantile(_percentile_threshold);
    }

public:
    TopN(std::string schema_key, std::string item_key, std::initializer_list<std::string> names, std::string desc)
        : Metric(schema_key, names, std::move(desc))
        , _fi(MAX_FI_MAP_SIZE, START_FI_MAP_SIZE)
        , _item_key(item_key)
    {
    }

    void update(const T &value, uint64_t weight = 1)
    {
        _fi.update(value, weight);
    }

    void update(T &&value, uint64_t weight = 1)
    {
        _fi.update(value, weight);
    }

    void merge(const TopN &other)
    {
        _fi.merge(other._fi);
    }

    void set_settings(const size_t top_count, uint64_t percentile_threshold)
    {
        _top_count = top_count;
        _percentile_threshold = static_cast<double>(percentile_threshold) / 100;
        if (_percentile_threshold > 1.0) {
            throw std::runtime_error("threshold must be between 0 and 100 but has value " + std::to_string(_percentile_threshold));
        }
    }

    size_t topn_count() const
    {
        return _top_count;
    }

    double percentile_threshold() const
    {
        return _percentile_threshold;
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
        auto threshold = _get_threshold(items);
        for (uint64_t i = 0; i < std::min(_top_count, items.size()); i++) {
            if (items[i].get_estimate() >= threshold) {
                section[i]["name"] = formatter(items[i].get_item());
                section[i]["estimate"] = items[i].get_estimate();
            } else {
                break;
            }
        }
        name_json_assign(j, section);
    }

    void to_json(json &j, std::function<void(json &, const std::string &, const T &)> formatter) const
    {
        auto section = json::array();
        auto items = _fi.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        auto threshold = _get_threshold(items);
        for (uint64_t i = 0; i < std::min(_top_count, items.size()); i++) {
            if (items[i].get_estimate() >= threshold) {
                formatter(section[i], "name", items[i].get_item());
                section[i]["estimate"] = items[i].get_estimate();
            } else {
                break;
            }
        }
        name_json_assign(j, section);
    }

    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels, std::function<std::string(const T &)> formatter) const
    {
        LabelMap l(add_labels);
        auto items = _fi.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        auto threshold = _get_threshold(items);
        out << "# HELP " << base_name_snake() << ' ' << _desc << std::endl;
        out << "# TYPE " << base_name_snake() << " gauge" << std::endl;
        for (uint64_t i = 0; i < std::min(_top_count, items.size()); i++) {
            if (items[i].get_estimate() >= threshold) {
                l[_item_key] = formatter(items[i].get_item());
                out << name_snake({}, l) << ' ' << items[i].get_estimate() << std::endl;
            } else {
                break;
            }
        }
    }

    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels, std::function<void(LabelMap &, const std::string &, const T &)> formatter) const
    {
        LabelMap l(add_labels);
        auto items = _fi.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        auto threshold = _get_threshold(items);
        out << "# HELP " << base_name_snake() << ' ' << _desc << std::endl;
        out << "# TYPE " << base_name_snake() << " gauge" << std::endl;
        for (uint64_t i = 0; i < std::min(_top_count, items.size()); i++) {
            if (items[i].get_estimate() >= threshold) {
                formatter(l, _item_key, items[i].get_item());
                out << name_snake({}, l) << ' ' << items[i].get_estimate() << std::endl;
            } else {
                break;
            }
        }
    }

    // Metric
    void to_json(json &j) const override
    {
        auto section = json::array();
        auto items = _fi.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        auto threshold = _get_threshold(items);
        for (uint64_t i = 0; i < std::min(_top_count, items.size()); i++) {
            if (items[i].get_estimate() >= threshold) {
                section[i]["name"] = items[i].get_item();
                section[i]["estimate"] = items[i].get_estimate();
            } else {
                break;
            }
        }
        name_json_assign(j, section);
    }

    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override
    {
        LabelMap l(add_labels);
        auto items = _fi.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        auto threshold = _get_threshold(items);
        out << "# HELP " << base_name_snake() << ' ' << _desc << std::endl;
        out << "# TYPE " << base_name_snake() << " gauge" << std::endl;
        for (uint64_t i = 0; i < std::min(_top_count, items.size()); i++) {
            if (items[i].get_estimate() >= threshold) {
                std::stringstream name_text;
                name_text << items[i].get_item();
                l[_item_key] = name_text.str();
                out << name_snake({}, l) << ' ' << items[i].get_estimate() << std::endl;
            } else {
                break;
            }
        }
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
    Cardinality(std::string schema_key, std::initializer_list<std::string> names, std::string desc)
        : Metric(schema_key, names, std::move(desc))
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
    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override;
};

/**
 * A Rate metric class which knows how to render its output. Note that this is only useful for "live" rates,
 * that is, calculating rates in real time and not from pre recorded streams
 *
 * NOTE: this class _is_ thread safe, it _does not_ need an additional mutex
 */
class Rate final : public Metric
{
    std::atomic_uint64_t _counter;
    std::atomic_uint64_t _rate;
    mutable std::shared_mutex _sketch_mutex;
    Quantile<int_fast32_t> _quantile;

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
    Rate(std::string schema_key, std::initializer_list<std::string> names, std::string desc)
        : Metric(schema_key, names, desc)
        , _counter(0)
        , _rate(0)
        , _quantile(schema_key, names, std::move(desc))
    {
        _start_timer();
    }

    ~Rate()
    {
        cancel();
    }

    /**
     * stop rate collection, ie. expect no more counter updates.
     * does not affect the quantiles - in effect, it makes the rate read only
     */
    void cancel()
    {
        _timer_handle->cancel();
        std::unique_lock w_lock(_sketch_mutex);
        _rate.store(0, std::memory_order_relaxed);
        _counter.store(0, std::memory_order_relaxed);
    }

    Rate &operator++()
    {
        _counter.fetch_add(1, std::memory_order_relaxed);
        return *this;
    }

    void operator+=(uint64_t i)
    {
        _counter.fetch_add(i, std::memory_order_relaxed);
    }

    uint64_t rate() const
    {
        return _rate.load(std::memory_order_relaxed);
    }

    void merge(const Rate &other, Aggregate agg_operator)
    {
        std::shared_lock r_lock(other._sketch_mutex);
        std::unique_lock w_lock(_sketch_mutex);
        _quantile.merge(other._quantile, agg_operator);
        // the live rate is simply copied if non zero
        if (other._rate != 0) {
            _rate.store(other._rate, std::memory_order_relaxed);
        }
    }

    void to_json(json &j, bool include_live) const;

    // Metric
    void to_json(json &j) const override;
    void to_prometheus(std::stringstream &out, Metric::LabelMap add_labels = {}) const override;
};

}