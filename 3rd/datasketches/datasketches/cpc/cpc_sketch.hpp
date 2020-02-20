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

#ifndef CPC_SKETCH_HPP_
#define CPC_SKETCH_HPP_

#include <iostream>
#include <functional>
#include <string>
#include <vector>

#if defined(_MSC_VER)
#include <iso646.h> // for and/or keywords
#endif // _MSC_VER

#include "u32_table.hpp"
#include "cpc_common.hpp"
#include "cpc_compressor.hpp"
#include "cpc_confidence.hpp"

namespace datasketches {

/*
 * High performance C++ implementation of Compressed Probabilistic Counting (CPC) Sketch
 *
 * This is a very compact (in serialized form) distinct counting sketch.
 * The theory is described in the following paper:
 * https://arxiv.org/abs/1708.06839
 *
 * author Kevin Lang
 * author Alexander Saydakov
 */

// forward-declarations
template<typename A> class cpc_sketch_alloc;
template<typename A> class cpc_union_alloc;

// alias with default allocator for convenience
typedef cpc_sketch_alloc<std::allocator<void>> cpc_sketch;

// allocation and initialization of global decompression (decoding) tables
// call this before anything else if you want to control the initialization time
// for instance, to have this happen outside of a transaction context
// otherwise initialization happens on the first use (serialization or deserialization)
// it is safe to call more than once assuming no race conditions
// this is not thread safe! neither is the rest of the library
template<typename A> void cpc_init();

template<typename A>
class cpc_sketch_alloc {
  public:

    explicit cpc_sketch_alloc(uint8_t lg_k = CPC_DEFAULT_LG_K, uint64_t seed = DEFAULT_SEED);
    uint8_t get_lg_k() const;
    bool is_empty() const;
    double get_estimate() const;
    double get_lower_bound(unsigned kappa) const;
    double get_upper_bound(unsigned kappa) const;

    void update(const std::string& value);
    void update(uint64_t value);
    void update(int64_t value);

    // for compatibility with Java implementation
    void update(uint32_t value);
    void update(int32_t value);
    void update(uint16_t value);
    void update(int16_t value);
    void update(uint8_t value);
    void update(int8_t value);
    void update(double value);
    void update(float value);

    // This is a "universal" update that covers all cases above, but may produce different hashes
    // Be very careful to hash input values consistently using the same approach over time,
    // on different platforms and while passing sketches from or to Java environment
    // Otherwise two sketches that should represent overlapping sets will be disjoint
    // For instance, for signed 32-bit values call update(int32_t) method above,
    // which does widening conversion to int64_t, if compatibility with Java is expected
    void update(const void* value, int size);

    // prints a sketch summary to a given stream
    void to_stream(std::ostream& os) const;

    void serialize(std::ostream& os) const;
    typedef vector_u8<A> vector_bytes; // alias for users
    vector_bytes serialize(unsigned header_size_bytes = 0) const;

    static cpc_sketch_alloc<A> deserialize(std::istream& is, uint64_t seed = DEFAULT_SEED);
    static cpc_sketch_alloc<A> deserialize(const void* bytes, size_t size, uint64_t seed = DEFAULT_SEED);

    // for internal use
    uint32_t get_num_coupons() const;

    // for debugging
    // this should catch some forms of corruption during serialization-deserialization
    bool validate() const;

  private:
    static const uint8_t SERIAL_VERSION = 1;
    static const uint8_t FAMILY = 16;

    enum flags { IS_BIG_ENDIAN, IS_COMPRESSED, HAS_HIP, HAS_TABLE, HAS_WINDOW };

    // Note: except for brief transitional moments, these sketches always obey
    // the following strict mapping between the flavor of a sketch and the
    // number of coupons that it has collected
    enum flavor {
      EMPTY,   //     0 == C <     1
      SPARSE,  //     1 <= C < 3K/32
      HYBRID,  // 3K/32 <= C <   K/2
      PINNED,  //   K/2 <= C < 27K/8  [NB: 27/8 = 3 + 3/8]
      SLIDING  // 27K/8 <= C
    };

    uint8_t lg_k;
    uint64_t seed;
    bool was_merged; // is the sketch the result of merging?
    uint32_t num_coupons; // the number of coupons collected so far

    u32_table<A> surprising_value_table;
    vector_u8<A> sliding_window;
    uint8_t window_offset; // derivable from num_coupons, but made explicit for speed
    uint8_t first_interesting_column; // This is part of a speed optimization

    double kxp;
    double hip_est_accum;

    // for deserialization and cpc_union::get_result()
    cpc_sketch_alloc(uint8_t lg_k, uint32_t num_coupons, uint8_t first_interesting_column, u32_table<A>&& table,
        vector_u8<A>&& window, bool has_hip, double kxp, double hip_est_accum, uint64_t seed);

    inline void row_col_update(uint32_t row_col);
    inline void update_sparse(uint32_t row_col);
    inline void update_windowed(uint32_t row_col);
    inline void update_hip(uint32_t row_col);
    void promote_sparse_to_windowed();
    void move_window();
    void refresh_kxp(const uint64_t* bit_matrix);

    friend double get_hip_confidence_lb<A>(const cpc_sketch_alloc<A>& sketch, int kappa);
    friend double get_hip_confidence_ub<A>(const cpc_sketch_alloc<A>& sketch, int kappa);
    friend double get_icon_confidence_lb<A>(const cpc_sketch_alloc<A>& sketch, int kappa);
    friend double get_icon_confidence_ub<A>(const cpc_sketch_alloc<A>& sketch, int kappa);
    double get_hip_estimate() const;
    double get_icon_estimate() const;

    inline flavor determine_flavor() const;
    static inline flavor determine_flavor(uint8_t lg_k, uint64_t c);

    static inline uint8_t determine_correct_offset(uint8_t lg_k, uint64_t c);

    // this produces a full-size k-by-64 bit matrix
    vector_u64<A> build_bit_matrix() const;

    static uint8_t get_preamble_ints(uint32_t num_coupons, bool has_hip, bool has_table, bool has_window);
    inline void write_hip(std::ostream& os) const;
    inline size_t copy_hip_to_mem(void* dst) const;

    friend cpc_compressor<A>;
    friend cpc_union_alloc<A>;
};

} /* namespace datasketches */

#include "cpc_sketch_impl.hpp"

#endif
