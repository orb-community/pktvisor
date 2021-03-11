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

add_library(cpc INTERFACE)

add_library(${PROJECT_NAME}::CPC ALIAS cpc)

if (BUILD_TESTS)
  add_subdirectory(test)
endif()

target_include_directories(cpc
  INTERFACE
    $<INSTALL_INTERFACE:$<INSTALL_PREFIX>/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_link_libraries(cpc INTERFACE common)
target_compile_features(cpc INTERFACE cxx_std_11)

set(cpc_HEADERS "")
list(APPEND cpc_HEADERS "include/compression_data.hpp")
list(APPEND cpc_HEADERS "include/cpc_common.hpp")
list(APPEND cpc_HEADERS "include/cpc_compressor.hpp")
list(APPEND cpc_HEADERS "include/cpc_compressor_impl.hpp")
list(APPEND cpc_HEADERS "include/cpc_confidence.hpp")
list(APPEND cpc_HEADERS "include/cpc_sketch.hpp")
list(APPEND cpc_HEADERS "include/cpc_sketch_impl.hpp")
list(APPEND cpc_HEADERS "include/cpc_union.hpp")
list(APPEND cpc_HEADERS "include/cpc_union_impl.hpp")
list(APPEND cpc_HEADERS "include/cpc_util.hpp")
list(APPEND cpc_HEADERS "include/icon_estimator.hpp")
list(APPEND cpc_HEADERS "include/kxp_byte_lookup.hpp")
list(APPEND cpc_HEADERS "include/u32_table.hpp")
list(APPEND cpc_HEADERS "include/u32_table_impl.hpp")

install(TARGETS cpc
  EXPORT ${PROJECT_NAME}
)

install(FILES ${cpc_HEADERS}
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/DataSketches")

target_sources(cpc
  INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include/compression_data.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cpc_common.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cpc_compressor.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cpc_compressor_impl.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cpc_confidence.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cpc_sketch.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cpc_sketch_impl.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cpc_union.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cpc_union_impl.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/cpc_util.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/icon_estimator.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/kxp_byte_lookup.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/u32_table.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/u32_table_impl.hpp
)
