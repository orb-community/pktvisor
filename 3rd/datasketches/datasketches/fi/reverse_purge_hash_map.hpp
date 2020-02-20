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

#ifndef REVERSE_PURGE_HASH_MAP_HPP_
#define REVERSE_PURGE_HASH_MAP_HPP_

#include <memory>
#include <algorithm>
#include <iterator>
#include <cmath>

#if defined(_MSC_VER)
#include <iso646.h> // for and/or keywords
#endif // _MSC_VER

namespace datasketches {

/*
 * Based on Java implementation here:
 * https://github.com/DataSketches/sketches-core/blob/master/src/main/java/com/yahoo/sketches/frequencies/ReversePurgeItemHashMap.java
 * author Alexander Saydakov
 */

template<typename T, typename H = std::hash<T>, typename E = std::equal_to<T>, typename A = std::allocator<T>>
class reverse_purge_hash_map {
  typedef typename std::allocator_traits<A>::template rebind_alloc<uint16_t> AllocU16;
  typedef typename std::allocator_traits<A>::template rebind_alloc<uint64_t> AllocU64;

public:
  reverse_purge_hash_map(uint8_t lg_size, uint8_t lg_max_size);
  reverse_purge_hash_map(const reverse_purge_hash_map& other);
  reverse_purge_hash_map(reverse_purge_hash_map&& other) noexcept;
  ~reverse_purge_hash_map();
  reverse_purge_hash_map& operator=(reverse_purge_hash_map other);
  reverse_purge_hash_map& operator=(reverse_purge_hash_map&& other);
  uint64_t adjust_or_insert(const T& key, uint64_t value);
  uint64_t adjust_or_insert(T&& key, uint64_t value);
  uint64_t get(const T& key) const;
  uint8_t get_lg_cur_size() const;
  uint8_t get_lg_max_size() const;
  uint32_t get_capacity() const;
  uint32_t get_num_active() const;
  class const_iterator;
  const_iterator begin() const;
  const_iterator end() const;
private:
  static constexpr double LOAD_FACTOR = 0.75;
  static constexpr uint16_t DRIFT_LIMIT = 1024; // used only for stress testing
  static constexpr uint32_t MAX_SAMPLE_SIZE = 1024; // number of samples to compute approximate median during purge

  uint8_t lg_cur_size;
  uint8_t lg_max_size;
  uint32_t num_active;
  T* keys;
  uint64_t* values;
  uint16_t* states;

  inline bool is_active(uint32_t probe) const;
  void subtract_and_keep_positive_only(uint64_t amount);
  void hash_delete(uint32_t probe);
  uint32_t internal_adjust_or_insert(const T& key, uint64_t value);
  uint64_t resize_or_purge_if_needed();
  void resize(uint8_t lg_new_size);
  uint64_t purge();
};

// clang++ seems to require this declaration for CMAKE_BUILD_TYPE='Debug"
template<typename T, typename H, typename E, typename A>
constexpr uint32_t reverse_purge_hash_map<T, H, E, A>::MAX_SAMPLE_SIZE;

// This iterator uses strides based on golden ratio to avoid clustering during merge
template<typename T, typename H, typename E, typename A>
class reverse_purge_hash_map<T, H, E, A>::const_iterator: public std::iterator<std::input_iterator_tag, T> {
public:
  friend class reverse_purge_hash_map<T, H, E, A>;
  const_iterator(const const_iterator& other) : map(other.map), index(other.index), count(other.count), stride(other.stride) {}
  const_iterator& operator++() {
    ++count;
    if (count < map->num_active) {
      const uint32_t mask = (1 << map->lg_cur_size) - 1;
      do {
        index = (index + stride) & mask;
      } while (!map->is_active(index));
    }
    return *this;
  }
  const_iterator operator++(int) { const_iterator tmp(*this); operator++(); return tmp; }
  bool operator==(const const_iterator& rhs) const { return count == rhs.count; }
  bool operator!=(const const_iterator& rhs) const { return count != rhs.count; }
  const std::pair<const T&, const uint64_t> operator*() const {
    return std::pair<const T&, const uint64_t>(map->keys[index], map->values[index]);
  }
private:
  static constexpr double GOLDEN_RATIO_RECIPROCAL = 0.6180339887498949; // = (sqrt(5) - 1) / 2
  const reverse_purge_hash_map<T, H, E, A>* map;
  uint32_t index;
  uint32_t count;
  uint32_t stride;
  const_iterator(const reverse_purge_hash_map<T, H, E, A>* map, uint32_t index, uint32_t count):
    map(map), index(index), count(count), stride(static_cast<uint32_t>((1 << map->lg_cur_size) * GOLDEN_RATIO_RECIPROCAL) | 1) {}
};

template<typename T, typename H, typename E, typename A>
reverse_purge_hash_map<T, H, E, A>::reverse_purge_hash_map(uint8_t lg_cur_size, uint8_t lg_max_size):
lg_cur_size(lg_cur_size),
lg_max_size(lg_max_size),
num_active(0),
keys(A().allocate(1 << lg_cur_size)),
values(AllocU64().allocate(1 << lg_cur_size)),
states(AllocU16().allocate(1 << lg_cur_size))
{
  std::fill(states, &states[1 << lg_cur_size], 0);
}

template<typename T, typename H, typename E, typename A>
reverse_purge_hash_map<T, H, E, A>::reverse_purge_hash_map(const reverse_purge_hash_map<T, H, E, A>& other):
lg_cur_size(other.lg_cur_size),
lg_max_size(other.lg_max_size),
num_active(other.num_active),
keys(A().allocate(1 << lg_cur_size)),
values(AllocU64().allocate(1 << lg_cur_size)),
states(AllocU16().allocate(1 << lg_cur_size))
{
  const uint32_t size = 1 << lg_cur_size;
  if (num_active > 0) {
    auto num = num_active;
    for (uint32_t i = 0; i < size; i++) {
      if (other.states[i] > 0) {
        new (&keys[i]) T(other.keys[i]);
        values[i] = other.values[i];
      }
      if (--num == 0) break;
    }
  }
  std::copy(&other.states[0], &other.states[size], states);
}

template<typename T, typename H, typename E, typename A>
reverse_purge_hash_map<T, H, E, A>::reverse_purge_hash_map(reverse_purge_hash_map<T, H, E, A>&& other) noexcept:
lg_cur_size(other.lg_cur_size),
lg_max_size(other.lg_max_size),
num_active(other.num_active),
keys(nullptr),
values(nullptr),
states(nullptr)
{
  std::swap(keys, other.keys);
  std::swap(values, other.values);
  std::swap(states, other.states);
  other.num_active = 0;
}

template<typename T, typename H, typename E, typename A>
reverse_purge_hash_map<T, H, E, A>::~reverse_purge_hash_map() {
  const uint32_t size = 1 << lg_cur_size;
  if (num_active > 0) {
    for (uint32_t i = 0; i < size; i++) {
      if (is_active(i)) {
          keys[i].~T();
          if (--num_active == 0) break;
      }
    }
  }
  A().deallocate(keys, size);
  AllocU64().deallocate(values, size);
  AllocU16().deallocate(states, size);
}

template<typename T, typename H, typename E, typename A>
reverse_purge_hash_map<T, H, E, A>& reverse_purge_hash_map<T, H, E, A>::operator=(reverse_purge_hash_map<T, H, E, A> other) {
  std::swap(lg_cur_size, other.lg_cur_size);
  std::swap(lg_max_size, other.lg_max_size);
  std::swap(num_active, other.num_active);
  std::swap(keys, other.keys);
  std::swap(values, other.values);
  std::swap(states, other.states);
  return *this;
}

template<typename T, typename H, typename E, typename A>
reverse_purge_hash_map<T, H, E, A>& reverse_purge_hash_map<T, H, E, A>::operator=(reverse_purge_hash_map<T, H, E, A>&& other) {
  std::swap(lg_cur_size, other.lg_cur_size);
  std::swap(lg_max_size, other.lg_max_size);
  std::swap(num_active, other.num_active);
  std::swap(keys, other.keys);
  std::swap(values, other.values);
  std::swap(states, other.states);
  return *this;
}

template<typename T, typename H, typename E, typename A>
uint64_t reverse_purge_hash_map<T, H, E, A>::adjust_or_insert(const T& key, uint64_t value) {
  const uint32_t num_active_before = num_active;
  const uint32_t index = internal_adjust_or_insert(key, value);
  if (num_active > num_active_before) {
    new (&keys[index]) T(key);
    return resize_or_purge_if_needed();
  }
  return 0;
}

template<typename T, typename H, typename E, typename A>
uint64_t reverse_purge_hash_map<T, H, E, A>::adjust_or_insert(T&& key, uint64_t value) {
  const uint32_t num_active_before = num_active;
  const uint32_t index = internal_adjust_or_insert(key, value);
  if (num_active > num_active_before) {
    new (&keys[index]) T(std::move(key));
    return resize_or_purge_if_needed();
  }
  return 0;
}

template<typename T, typename H, typename E, typename A>
uint64_t reverse_purge_hash_map<T, H, E, A>::get(const T& key) const {
  const uint32_t mask = (1 << lg_cur_size) - 1;
  uint32_t probe = H()(key) & mask;
  while (is_active(probe)) {
    if (E()(keys[probe], key)) return values[probe];
    probe = (probe + 1) & mask;
  }
  return 0;
}

template<typename T, typename H, typename E, typename A>
uint8_t reverse_purge_hash_map<T, H, E, A>::get_lg_cur_size() const {
  return lg_cur_size;
}

template<typename T, typename H, typename E, typename A>
uint8_t reverse_purge_hash_map<T, H, E, A>::get_lg_max_size() const {
  return lg_max_size;
}

template<typename T, typename H, typename E, typename A>
uint32_t reverse_purge_hash_map<T, H, E, A>::get_capacity() const {
  return (1 << lg_cur_size) * LOAD_FACTOR;
}

template<typename T, typename H, typename E, typename A>
uint32_t reverse_purge_hash_map<T, H, E, A>::get_num_active() const {
  return num_active;
}

template<typename T, typename H, typename E, typename A>
typename reverse_purge_hash_map<T, H, E, A>::const_iterator reverse_purge_hash_map<T, H, E, A>::begin() const {
  const uint32_t size = 1 << lg_cur_size;
  uint32_t i = 0;
  while (i < size and !is_active(i)) i++;
  return reverse_purge_hash_map<T, H, E, A>::const_iterator(this, i, 0);
}

template<typename T, typename H, typename E, typename A>
typename reverse_purge_hash_map<T, H, E, A>::const_iterator reverse_purge_hash_map<T, H, E, A>::end() const {
  return reverse_purge_hash_map<T, H, E, A>::const_iterator(this, 1 << lg_cur_size, num_active);
}

template<typename T, typename H, typename E, typename A>
bool reverse_purge_hash_map<T, H, E, A>::is_active(uint32_t index) const {
  return states[index] > 0;
}

template<typename T, typename H, typename E, typename A>
void reverse_purge_hash_map<T, H, E, A>::subtract_and_keep_positive_only(uint64_t amount) {
  // starting from the back, find the first empty cell,
  // which establishes the high end of a cluster.
  uint32_t first_probe = (1 << lg_cur_size) - 1;
  while (is_active(first_probe)) first_probe--;
  // when we find the next non-empty cell, we know we are at the high end of a cluster
  // work towards the front, delete any non-positive entries.
  for (uint32_t probe = first_probe; probe-- > 0;) {
    if (is_active(probe)) {
      if (values[probe] <= amount) {
        hash_delete(probe); // does the work of deletion and moving higher items towards the front
        num_active--;
      } else {
        values[probe] -= amount;
      }
    }
  }
  // now work on the first cluster that was skipped
  for (uint32_t probe = (1 << lg_cur_size); probe-- > first_probe;) {
    if (is_active(probe)) {
      if (values[probe] <= amount) {
        hash_delete(probe);
        num_active--;
      } else {
        values[probe] -= amount;
      }
    }
  }
}

template<typename T, typename H, typename E, typename A>
void reverse_purge_hash_map<T, H, E, A>::hash_delete(uint32_t delete_index) {
  // Looks ahead in the table to search for another
  // item to move to this location
  // if none are found, the status is changed
  states[delete_index] = 0; // mark as empty
  keys[delete_index].~T();
  uint32_t drift = 1;
  const uint32_t mask = (1 << lg_cur_size) - 1;
  uint32_t probe = (delete_index + drift) & mask; // map length must be a power of 2
  // advance until we find a free location replacing locations as needed
  while (is_active(probe)) {
    if (states[probe] > drift) {
      // move current element
      new (&keys[delete_index]) T(std::move(keys[probe]));
      values[delete_index] = values[probe];
      states[delete_index] = states[probe] - drift;
      states[probe] = 0; // mark as empty
      keys[probe].~T();
      drift = 0;
      delete_index = probe;
    }
    probe = (probe + 1) & mask;
    drift++;
    // only used for theoretical analysis
    if (drift >= DRIFT_LIMIT) throw std::logic_error("drift: " + std::to_string(drift) + " >= DRIFT_LIMIT");
  }
}

template<typename T, typename H, typename E, typename A>
uint32_t reverse_purge_hash_map<T, H, E, A>::internal_adjust_or_insert(const T& key, uint64_t value) {
  const uint32_t mask = (1 << lg_cur_size) - 1;
  uint32_t index = H()(key) & mask;
  uint16_t drift = 1;
  while (is_active(index)) {
    if (E()(keys[index], key)) {
      // adjusting the value of an existing key
      values[index] += value;
      return index;
    }
    index = (index + 1) & mask;
    drift++;
    // only used for theoretical analysis
    if (drift >= DRIFT_LIMIT) throw std::logic_error("drift limit reached");
  }
  // adding the key and value to the table
  if (num_active > get_capacity()) {
    throw std::logic_error("num_active " + std::to_string(num_active) + " > capacity " + std::to_string(get_capacity()));
  }
  values[index] = value;
  states[index] = drift;
  num_active++;
  return index;
}

template<typename T, typename H, typename E, typename A>
uint64_t reverse_purge_hash_map<T, H, E, A>::resize_or_purge_if_needed() {
  if (num_active > get_capacity()) {
    if (lg_cur_size < lg_max_size) { // can grow
      resize(lg_cur_size + 1);
    } else { // at target size, must purge
      const uint64_t offset = purge();
      if (num_active > get_capacity()) {
        throw std::logic_error("purge did not reduce number of active items");
      }
      return offset;
    }
  }
  return 0;
}

template<typename T, typename H, typename E, typename A>
void reverse_purge_hash_map<T, H, E, A>::resize(uint8_t lg_new_size) {
  const uint32_t old_size = 1 << lg_cur_size;
  T* old_keys = keys;
  uint64_t* old_values = values;
  uint16_t* old_states = states;
  const uint32_t new_size = 1 << lg_new_size;
  keys = A().allocate(new_size);
  values = AllocU64().allocate(new_size);
  states = AllocU16().allocate(new_size);
  std::fill(states, &states[new_size], 0);
  num_active = 0;
  lg_cur_size = lg_new_size;
  for (uint32_t i = 0; i < old_size; i++) {
    if (old_states[i] > 0) {
      adjust_or_insert(std::move(old_keys[i]), old_values[i]);
      old_keys[i].~T();
    }
  }
  A().deallocate(old_keys, old_size);
  AllocU64().deallocate(old_values, old_size);
  AllocU16().deallocate(old_states, old_size);
}

template<typename T, typename H, typename E, typename A>
uint64_t reverse_purge_hash_map<T, H, E, A>::purge() {
  const uint32_t limit = std::min(MAX_SAMPLE_SIZE, num_active);
  uint32_t num_samples = 0;
  uint32_t i = 0;
  uint64_t* samples = AllocU64().allocate(limit);
  while (num_samples < limit) {
    if (is_active(i)) {
      samples[num_samples++] = values[i];
    }
    i++;
  }
  std::nth_element(&samples[0], &samples[num_samples / 2], &samples[num_samples - 1]);
  const uint64_t median = samples[num_samples / 2];
  AllocU64().deallocate(samples, limit);
  subtract_and_keep_positive_only(median);
  return median;
}

} /* namespace datasketches */

# endif
