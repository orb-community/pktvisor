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

add_library(kll INTERFACE)

add_library(${PROJECT_NAME}::KLL ALIAS kll)

target_include_directories(kll
		INTERFACE
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
		$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/include>
		)

target_link_libraries(kll INTERFACE common)
target_compile_features(kll INTERFACE cxx_std_11)

set(kll_HEADERS "")
list(APPEND kll_HEADERS "include/kll_sketch.hpp")
list(APPEND kll_HEADERS "include/kll_sketch_impl.hpp")
list(APPEND kll_HEADERS "include/kll_helper.hpp")
list(APPEND kll_HEADERS "include/kll_helper_impl.hpp")

install(TARGETS kll
		EXPORT ${PROJECT_NAME}
		)

install(FILES ${kll_HEADERS}
		DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/DataSketches")

target_sources(kll
		INTERFACE
		${CMAKE_CURRENT_SOURCE_DIR}/include/kll_helper.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/kll_helper_impl.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/kll_sketch.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/kll_sketch_impl.hpp
		)