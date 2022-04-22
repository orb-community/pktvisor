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

#ifndef _COMMON_DEFS_HPP_
#define _COMMON_DEFS_HPP_

#include <cstdint>
#include <string>
#include <memory>

namespace datasketches {

static const uint64_t DEFAULT_SEED = 9001;

template<typename A> using AllocChar = typename std::allocator_traits<A>::template rebind_alloc<char>;
template<typename A> using string = std::basic_string<char, std::char_traits<char>, AllocChar<A>>;

// utility function to hide unused compiler warning
// usually has no additional cost
template<typename T> void unused(T&&...) {}

// common helping functions
// TODO: find a better place for them

constexpr uint8_t log2(uint32_t n) {
  return (n > 1) ? 1 + log2(n >> 1) : 0;
}

constexpr uint8_t lg_size_from_count(uint32_t n, double load_factor) {
  return log2(n) + ((n > static_cast<uint32_t>((1 << (log2(n) + 1)) * load_factor)) ? 2 : 1);
}

} // namespace

#endif // _COMMON_DEFS_HPP_
