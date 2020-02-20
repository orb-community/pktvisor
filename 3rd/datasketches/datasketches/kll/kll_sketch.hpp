/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef KLL_SKETCH_HPP_
#define KLL_SKETCH_HPP_

#include <functional>
#include <memory>
#include <vector>

#if defined(_MSC_VER)
#include <iso646.h> // for and/or keywords
#endif // _MSC_VER

#include "kll_quantile_calculator.hpp"
#include "serde.hpp"

namespace datasketches {

/*
 * Implementation of a very compact quantiles sketch with lazy compaction scheme
 * and nearly optimal accuracy per retained item.
 * See <a href="https://arxiv.org/abs/1603.05346v2">Optimal Quantile Approximation in Streams</a>.
 *
 * <p>This is a stochastic streaming sketch that enables near-real time analysis of the
 * approximate distribution of values from a very large stream in a single pass, requiring only
 * that the values are comparable.
 * The analysis is obtained using <i>get_quantile()</i> or <i>get_quantiles()</i> functions or the
 * inverse functions get_rank(), get_PMF() (Probability Mass Function), and get_CDF()
 * (Cumulative Distribution Function).
 *
 * <p>Given an input stream of <i>N</i> numeric values, the <i>absolute rank</i> of any specific
 * value is defined as its index <i>(0 to N-1)</i> in the hypothetical sorted stream of all
 * <i>N</i> input values.
 *
 * <p>The <i>normalized rank</i> (<i>rank</i>) of any specific value is defined as its
 * <i>absolute rank</i> divided by <i>N</i>.
 * Thus, the <i>normalized rank</i> is a value between zero and one.
 * In the documentation for this sketch <i>absolute rank</i> is never used so any
 * reference to just <i>rank</i> should be interpreted to mean <i>normalized rank</i>.
 *
 * <p>This sketch is configured with a parameter <i>k</i>, which affects the size of the sketch
 * and its estimation error.
 *
 * <p>The estimation error is commonly called <i>epsilon</i> (or <i>eps</i>) and is a fraction
 * between zero and one. Larger values of <i>k</i> result in smaller values of epsilon.
 * Epsilon is always with respect to the rank and cannot be applied to the
 * corresponding values.
 *
 * <p>The relationship between the normalized rank and the corresponding values can be viewed
 * as a two dimensional monotonic plot with the normalized rank on one axis and the
 * corresponding values on the other axis. If the y-axis is specified as the value-axis and
 * the x-axis as the normalized rank, then <i>y = get_quantile(x)</i> is a monotonically
 * increasing function.
 *
 * <p>The functions <i>get_quantile(rank)</i> and get_quantiles(...) translate ranks into
 * corresponding values. The functions <i>get_rank(value),
 * get_CDF(...) (Cumulative Distribution Function), and get_PMF(...)
 * (Probability Mass Function)</i> perform the opposite operation and translate values into ranks.
 *
 * <p>The <i>getPMF(...)</i> function has about 13 to 47% worse rank error (depending
 * on <i>k</i>) than the other queries because the mass of each "bin" of the PMF has
 * "double-sided" error from the upper and lower edges of the bin as a result of a subtraction,
 * as the errors from the two edges can sometimes add.
 *
 * <p>The default <i>k</i> of 200 yields a "single-sided" epsilon of about 1.33% and a
 * "double-sided" (PMF) epsilon of about 1.65%.
 *
 * <p>A <i>get_quantile(rank)</i> query has the following guarantees:
 * <ul>
 * <li>Let <i>v = get_quantile(r)</i> where <i>r</i> is the rank between zero and one.</li>
 * <li>The value <i>v</i> will be a value from the input stream.</li>
 * <li>Let <i>trueRank</i> be the true rank of <i>v</i> derived from the hypothetical sorted
 * stream of all <i>N</i> values.</li>
 * <li>Let <i>eps = get_normalized_rank_error(false)</i>.</li>
 * <li>Then <i>r - eps &le; trueRank &le; r + eps</i> with a confidence of 99%. Note that the
 * error is on the rank, not the value.</li>
 * </ul>
 *
 * <p>A <i>get_rank(value)</i> query has the following guarantees:
 * <ul>
 * <li>Let <i>r = get_rank(v)</i> where <i>v</i> is a value between the min and max values of
 * the input stream.</li>
 * <li>Let <i>true_rank</i> be the true rank of <i>v</i> derived from the hypothetical sorted
 * stream of all <i>N</i> values.</li>
 * <li>Let <i>eps = get_normalized_rank_error(false)</i>.</li>
 * <li>Then <i>r - eps &le; trueRank &le; r + eps</i> with a confidence of 99%.</li>
 * </ul>
 *
 * <p>A <i>get_PMF()</i> query has the following guarantees:
 * <ul>
 * <li>Let <i>{r1, r2, ..., r(m+1)} = get_PMF(v1, v2, ..., vm)</i> where <i>v1, v2</i> are values
 * between the min and max values of the input stream.
 * <li>Let <i>mass<sub>i</sub> = estimated mass between v<sub>i</sub> and v<sub>i+1</sub></i>.</li>
 * <li>Let <i>trueMass</i> be the true mass between the values of <i>v<sub>i</sub>,
 * v<sub>i+1</sub></i> derived from the hypothetical sorted stream of all <i>N</i> values.</li>
 * <li>Let <i>eps = get_normalized_rank_error(true)</i>.</li>
 * <li>then <i>mass - eps &le; trueMass &le; mass + eps</i> with a confidence of 99%.</li>
 * <li>r(m+1) includes the mass of all points larger than vm.</li>
 * </ul>
 *
 * <p>A <i>get_CDF(...)</i> query has the following guarantees;
 * <ul>
 * <li>Let <i>{r1, r2, ..., r(m+1)} = get_CDF(v1, v2, ..., vm)</i> where <i>v1, v2</i> are values
 * between the min and max values of the input stream.
 * <li>Let <i>mass<sub>i</sub> = r<sub>i+1</sub> - r<sub>i</sub></i>.</li>
 * <li>Let <i>trueMass</i> be the true mass between the true ranks of <i>v<sub>i</sub>,
 * v<sub>i+1</sub></i> derived from the hypothetical sorted stream of all <i>N</i> values.</li>
 * <li>Let <i>eps = get_normalized_rank_error(true)</i>.</li>
 * <li>then <i>mass - eps &le; trueMass &le; mass + eps</i> with a confidence of 99%.</li>
 * <li>1 - r(m+1) includes the mass of all points larger than vm.</li>
 * </ul>
 *
 * <p>From the above, it might seem like we could make some estimates to bound the
 * <em>value</em> returned from a call to <em>get_quantile()</em>. The sketch, however, does not
 * let us derive error bounds or confidences around values. Because errors are independent, we
 * can approximately bracket a value as shown below, but there are no error estimates available.
 * Additionally, the interval may be quite large for certain distributions.
 * <ul>
 * <li>Let <i>v = get_quantile(r)</i>, the estimated quantile value of rank <i>r</i>.</li>
 * <li>Let <i>eps = get_normalized_rank_error(false)</i>.</li>
 * <li>Let <i>v<sub>lo</sub></i> = estimated quantile value of rank <i>(r - eps)</i>.</li>
 * <li>Let <i>v<sub>hi</sub></i> = estimated quantile value of rank <i>(r + eps)</i>.</li>
 * <li>Then <i>v<sub>lo</sub> &le; v &le; v<sub>hi</sub></i>, with 99% confidence.</li>
 * </ul>
 *
 * author Kevin Lang
 * author Alexander Saydakov
 * author Lee Rhodes
 */

template<typename A> using AllocU8 = typename std::allocator_traits<A>::template rebind_alloc<uint8_t>;
template<typename A> using vector_u8 = std::vector<uint8_t, AllocU8<A>>;
template<typename A> using AllocD = typename std::allocator_traits<A>::template rebind_alloc<double>;
template<typename A> using vector_d = std::vector<double, AllocD<A>>;

template <typename T, typename C = std::less<T>, typename S = serde<T>, typename A = std::allocator<T>>
class kll_sketch {
  typedef typename std::allocator_traits<A>::template rebind_alloc<uint32_t> AllocU32;

  public:
    static const uint8_t DEFAULT_M = 8;
    static const uint16_t DEFAULT_K = 200;
    static const uint16_t MIN_K = DEFAULT_M;
    static const uint16_t MAX_K = (1 << 16) - 1;

    explicit kll_sketch(uint16_t k = DEFAULT_K);
    kll_sketch(const kll_sketch& other);
    kll_sketch(kll_sketch&& other) noexcept;
    ~kll_sketch();
    kll_sketch& operator=(const kll_sketch& other);
    kll_sketch& operator=(kll_sketch&& other);
    void update(const T& value);
    void update(T&& value);
    void merge(const kll_sketch& other);
    bool is_empty() const;
    uint64_t get_n() const;
    uint32_t get_num_retained() const;
    bool is_estimation_mode() const;
    T get_min_value() const;
    T get_max_value() const;
    T get_quantile(double fraction) const;
    std::vector<T, A> get_quantiles(const double* fractions, uint32_t size) const;
    double get_rank(const T& value) const;
    vector_d<A> get_PMF(const T* split_points, uint32_t size) const;
    vector_d<A> get_CDF(const T* split_points, uint32_t size) const;
    double get_normalized_rank_error(bool pmf) const;

    // implementation for fixed-size arithmetic types (integral and floating point)
    template<typename TT = T, typename std::enable_if<std::is_arithmetic<TT>::value, int>::type = 0>
    size_t get_serialized_size_bytes() const {
      if (is_empty()) { return EMPTY_SIZE_BYTES; }
      if (num_levels_ == 1 and get_num_retained() == 1) {
        return DATA_START_SINGLE_ITEM + sizeof(TT);
      }
      // the last integer in the levels_ array is not serialized because it can be derived
      return DATA_START + num_levels_ * sizeof(uint32_t) + (get_num_retained() + 2) * sizeof(TT);
    }

    // implementation for all other types
    template<typename TT = T, typename std::enable_if<!std::is_arithmetic<TT>::value, int>::type = 0>
    size_t get_serialized_size_bytes() const {
      if (is_empty()) { return EMPTY_SIZE_BYTES; }
      if (num_levels_ == 1 and get_num_retained() == 1) {
        return DATA_START_SINGLE_ITEM + S().size_of_item(items_[levels_[0]]);
      }
      // the last integer in the levels_ array is not serialized because it can be derived
      size_t size = DATA_START + num_levels_ * sizeof(uint32_t);
      size += S().size_of_item(*min_value_);
      size += S().size_of_item(*max_value_);
      for (auto& it: *this) size += S().size_of_item(it.first);
      return size;
    }

    // this may need to be specialized to return correct size if sizeof(T) does not match the actual serialized size of an item
    // this method is for the user's convenience to predict the sketch size before serialization
    // and is not used in the serialization and deserialization code
    // predicting the size before serialization may not make sense if the item type is not of a fixed size (like string)
    static size_t get_max_serialized_size_bytes(uint16_t k, uint64_t n);

    void serialize(std::ostream& os) const;
    typedef vector_u8<A> vector_bytes; // alias for users
    vector_bytes serialize(unsigned header_size_bytes = 0) const;
    static kll_sketch<T, C, S, A> deserialize(std::istream& is);
    static kll_sketch<T, C, S, A> deserialize(const void* bytes, size_t size);

    /*
     * Gets the normalized rank error given k and pmf.
     * k - the configuration parameter
     * pmf - if true, returns the "double-sided" normalized rank error for the get_PMF() function.
     * Otherwise, it is the "single-sided" normalized rank error for all the other queries.
     * Constants were derived as the best fit to 99 percentile empirically measured max error in thousands of trials
     */
    static double get_normalized_rank_error(uint16_t k, bool pmf);

    void to_stream(std::ostream& os, bool print_levels = false, bool print_items = false) const;

    class const_iterator;
    const_iterator begin() const;
    const_iterator end() const;

    #ifdef KLL_VALIDATION
    uint8_t get_num_levels() { return num_levels_; }
    uint32_t* get_levels() { return levels_; }
    T* get_items() { return items_; }
    #endif

  private:
    /* Serialized sketch layout:
     *  Adr:
     *      ||    7    |   6   |    5   |    4   |    3   |    2    |    1   |      0       |
     *  0   || unused  |   M   |--------K--------|  Flags |  FamID  | SerVer | PreambleInts |
     *      ||   15    |   14  |   13   |   12   |   11   |   10    |    9   |      8       |
     *  1   ||-----------------------------------N------------------------------------------|
     *      ||   23    |   22  |   21   |   20   |   19   |    18   |   17   |      16      |
     *  2   ||---------------data----------------|-unused-|numLevels|-------min K-----------|
     */

    static const size_t EMPTY_SIZE_BYTES = 8;
    static const size_t DATA_START_SINGLE_ITEM = 8;
    static const size_t DATA_START = 20;

    static const uint8_t SERIAL_VERSION_1 = 1;
    static const uint8_t SERIAL_VERSION_2 = 2;
    static const uint8_t FAMILY = 15;

    enum flags { IS_EMPTY, IS_LEVEL_ZERO_SORTED, IS_SINGLE_ITEM };

    static const uint8_t PREAMBLE_INTS_SHORT = 2; // for empty and single item
    static const uint8_t PREAMBLE_INTS_FULL = 5;

    uint16_t k_;
    uint8_t m_; // minimum buffer "width"
    uint16_t min_k_; // for error estimation after merging with different k
    uint64_t n_;
    uint8_t num_levels_;
    uint32_t* levels_;
    uint8_t levels_size_;
    T* items_;
    uint32_t items_size_;
    T* min_value_;
    T* max_value_;
    bool is_level_zero_sorted_;

    // for deserialization
    // the common part of the preamble was read and compatibility checks were done
    kll_sketch(uint16_t k, uint8_t flags_byte, std::istream& is);

    // for deserialization
    // the common part of the preamble was read and compatibility checks were done
    kll_sketch(uint16_t k, uint8_t flags_byte, const void* bytes, size_t size);

    // common update code
    inline uint32_t internal_update(const T& value);

    // The following code is only valid in the special case of exactly reaching capacity while updating.
    // It cannot be used while merging, while reducing k, or anything else.
    void compress_while_updating(void);

    uint8_t find_level_to_compact() const;
    void add_empty_top_level_to_completely_full_sketch();
    void sort_level_zero();
    std::unique_ptr<kll_quantile_calculator<T, C, A>, std::function<void(kll_quantile_calculator<T, C, A>*)>> get_quantile_calculator();
    vector_d<A> get_PMF_or_CDF(const T* split_points, uint32_t size, bool is_CDF) const;
    void increment_buckets_unsorted_level(uint32_t from_index, uint32_t to_index, uint64_t weight,
        const T* split_points, uint32_t size, double* buckets) const;
    void increment_buckets_sorted_level(uint32_t from_index, uint32_t to_index, uint64_t weight,
        const T* split_points, uint32_t size, double* buckets) const;
    void merge_higher_levels(const kll_sketch& other, uint64_t final_n);
    void populate_work_arrays(const kll_sketch& other, T* workbuf, uint32_t* worklevels, uint8_t provisional_num_levels);
    void assert_correct_total_weight() const;
    uint32_t safe_level_size(uint8_t level) const;
    uint32_t get_num_retained_above_level_zero() const;

    static void check_m(uint8_t m);
    static void check_preamble_ints(uint8_t preamble_ints, uint8_t flags_byte);
    static void check_serial_version(uint8_t serial_version);
    static void check_family_id(uint8_t family_id);

    // implementation for floating point types
    template<typename TT = T, typename std::enable_if<std::is_floating_point<TT>::value, int>::type = 0>
    static TT get_invalid_value() {
      return std::numeric_limits<TT>::quiet_NaN();
    }

    // implementation for all other types
    template<typename TT = T, typename std::enable_if<!std::is_floating_point<TT>::value, int>::type = 0>
    static TT get_invalid_value() {
      throw std::runtime_error("getting quantiles from empty sketch is not supported for this type of values");
    }

};

template<typename T, typename C, typename S, typename A>
class kll_sketch<T, C, S, A>::const_iterator: public std::iterator<std::input_iterator_tag, T> {
public:
  friend class kll_sketch<T, C, S, A>;
  const_iterator(const const_iterator& other);
  const_iterator& operator++();
  const_iterator& operator++(int);
  bool operator==(const const_iterator& other) const;
  bool operator!=(const const_iterator& other) const;
  const std::pair<const T&, const uint64_t> operator*() const;
private:
  const T* items;
  const uint32_t* levels;
  const uint8_t num_levels;
  uint32_t index;
  uint8_t level;
  uint64_t weight;
  const_iterator(const T* items, const uint32_t* levels, const uint8_t num_levels);
};

} /* namespace datasketches */

#include "kll_sketch_impl.hpp"

#endif
