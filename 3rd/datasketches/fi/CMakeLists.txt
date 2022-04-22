# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

add_library(fi INTERFACE)

add_library(${PROJECT_NAME}::FI ALIAS fi)

if (BUILD_TESTS)
  add_subdirectory(test)
endif()

target_include_directories(fi
  INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:$<INSTALL_PREFIX>/include>
)

target_link_libraries(fi INTERFACE common)
target_compile_features(fi INTERFACE cxx_std_11)

set(fi_HEADERS "")
list(APPEND fi_HEADERS "include/frequent_items_sketch.hpp")
list(APPEND fi_HEADERS "include/frequent_items_sketch_impl.hpp")
list(APPEND fi_HEADERS "include/reverse_purge_hash_map.hpp")
list(APPEND fi_HEADERS "include/reverse_purge_hash_map_impl.hpp")

install(TARGETS fi
  EXPORT ${PROJECT_NAME}
)

install(FILES ${fi_HEADERS}
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/DataSketches")

target_sources(fi
  INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include/frequent_items_sketch.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/frequent_items_sketch_impl.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/reverse_purge_hash_map.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/reverse_purge_hash_map_impl.hpp
)
