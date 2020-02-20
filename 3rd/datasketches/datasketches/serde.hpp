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

#ifndef DATASKETCHES_SERDE_HPP_
#define DATASKETCHES_SERDE_HPP_

#include <cstring>
#include <iostream>
#include <memory>
#include <string>

namespace datasketches {

// serialize and deserialize
template<typename T, typename Enable = void> struct serde {
  // stream serialization
  void serialize(std::ostream& os, const T* items, unsigned num);
  void deserialize(std::istream& is, T* items, unsigned num); // items are not initialized

  // raw bytes serialization
  size_t size_of_item(const T& item);
  size_t serialize(void* ptr, const T* items, unsigned num);
  size_t deserialize(const void* ptr, T* items, unsigned num); // items are not initialized
};

// serde for all fixed-size arithmetic types (int and float of different sizes)
// in particular, kll_sketch<int64_t> should produce sketches binary-compatible
// with LongsSketch and ItemsSketch<Long> with ArrayOfLongsSerDe in Java
template<typename T>
struct serde<T, typename std::enable_if<std::is_arithmetic<T>::value>::type> {
  void serialize(std::ostream& os, const T* items, unsigned num) {
    os.write((char*)items, sizeof(T) * num);
  }
  void deserialize(std::istream& is, T* items, unsigned num) {
    is.read((char*)items, sizeof(T) * num);
  }
  size_t size_of_item(T item) {
    return sizeof(T);
  }
  size_t serialize(void* ptr, const T* items, unsigned num) {
    memcpy(ptr, items, sizeof(T) * num);
    return sizeof(int32_t) * num;
  }
  size_t deserialize(const void* ptr, T* items, unsigned num) {
    memcpy(items, ptr, sizeof(T) * num);
    return sizeof(T) * num;
  }
};

// serde for std::string items
// This should produce sketches binary-compatible with
// ItemsSketch<String> with ArrayOfStringsSerDe in Java.
// The length of each string is stored as a 32-bit integer (historically),
// which may be too wasteful. Treat this as an example.
template<>
struct serde<std::string> {
  void serialize(std::ostream& os, const std::string* items, unsigned num) {
    for (unsigned i = 0; i < num; i++) {
      uint32_t length = items[i].size();
      os.write((char*)&length, sizeof(length));
      os.write(items[i].c_str(), length);
    }
  }
  void deserialize(std::istream& is, std::string* items, unsigned num) {
    for (unsigned i = 0; i < num; i++) {
      uint32_t length;
      is.read((char*)&length, sizeof(length));
      new (&items[i]) std::string;
      items[i].reserve(length);
      auto it = std::istreambuf_iterator<char>(is);
      for (uint32_t j = 0; j < length; j++) {
        items[i].push_back(*it);
        ++it;
      }
    }
  }
  size_t size_of_item(const std::string& item) {
    return sizeof(uint32_t) + item.size();
  }
  size_t serialize(void* ptr, const std::string* items, unsigned num) {
    size_t size = sizeof(uint32_t) * num;
    for (unsigned i = 0; i < num; i++) {
      uint32_t length = items[i].size();
      memcpy(ptr, &length, sizeof(length));
      ptr = static_cast<char*>(ptr) + sizeof(uint32_t);
      memcpy(ptr, items[i].c_str(), length);
      ptr = static_cast<char*>(ptr) + length;
      size += length;
    }
    return size;
  }
  size_t deserialize(const void* ptr, std::string* items, unsigned num) {
    size_t size = sizeof(uint32_t) * num;
    for (unsigned i = 0; i < num; i++) {
      uint32_t length;
      memcpy(&length, ptr, sizeof(length));
      ptr = static_cast<const char*>(ptr) + sizeof(uint32_t);
      new (&items[i]) std::string(static_cast<const char*>(ptr), length);
      ptr = static_cast<const char*>(ptr) + length;
      size += length;
    }
    return size;
  }
};

static inline size_t copy_from_mem(const void* src, void* dst, size_t size) {
  memcpy(dst, src, size);
  return size;
}

static inline size_t copy_to_mem(const void* src, void* dst, size_t size) {
  memcpy(dst, src, size);
  return size;
}

} /* namespace datasketches */

# endif
