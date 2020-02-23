cmake_minimum_required(VERSION 3.13)
project(pktvisor3)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# this is the source of truth for version, which will be written to config.h include file.
project(pktvisord VERSION 3.0.2)
set(PKTVISOR_VERSION_NUM ${PROJECT_VERSION})
set(PKTVISOR_VERSION "pktvisor ${PROJECT_VERSION}")

set(CMAKE_CXX_STANDARD 17)
add_compile_options(-Wall)

find_package(PkgConfig)

include(sanitizer)

pkg_check_modules(LIBPCPP REQUIRED PcapPlusPlus)

option(MMDB_ENABLE "Enable MaxMindDB support" OFF)
if (MMDB_ENABLE)
    pkg_check_modules(LIBMMDB REQUIRED libmaxminddb)
    message(STATUS "MaxMindDB support is enabled")
    add_library(geolite2cpp
            ${CMAKE_SOURCE_DIR}/3rd/geolite2cpp/src/GeoLite2PP.cpp
            ${CMAKE_SOURCE_DIR}/3rd/geolite2cpp/src/GeoLite2PP_error_category.cpp
            )
    target_include_directories(geolite2cpp
            PUBLIC
            ${CMAKE_SOURCE_DIR}/3rd/geolite2cpp/include
            ${LIBMMDB_INCLUDE_DIRS}
            )
    target_link_libraries(geolite2cpp
            PUBLIC
            ${LIBMMDB_LDFLAGS}
            ${LIBMMDB_LIBRARIES}
            )
else()
    message(STATUS "MaxMindDB support is disabled")
endif()

add_library(pktvisorcore
        src/querypairmgr.cpp
        src/tcpsession.cpp
        src/metrics.cpp
        src/utils.cpp
        )

target_include_directories(pktvisorcore
        PUBLIC
        ${LIBPCPP_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/3rd/datasketches
        ${CMAKE_SOURCE_DIR}/3rd/datasketches/datasketches
        ${CMAKE_SOURCE_DIR}/3rd
        )

if (APPLE)
target_link_libraries(pktvisorcore
        PRIVATE
        "-L ${LIBPCPP_LIBRARY_DIRS}"
        ${LIBPCPP_LIBRARIES}
        "-framework CoreFoundation"
        "-framework SystemConfiguration"
        )
else()
    target_link_libraries(pktvisorcore
            PRIVATE
            ${LIBPCPP_LDFLAGS}
            ${LIBPCPP_LIBRARIES}
            )
endif()

if (MMDB_ENABLE)
    target_include_directories(pktvisorcore
            PUBLIC
            ${LIBMMDB_INCLUDE_DIRS}
            ${CMAKE_SOURCE_DIR}/3rd/geolite2cpp/include
            )
    target_link_libraries(pktvisorcore PRIVATE geolite2cpp)
endif()

add_executable(pktvisord
        3rd/docopt/docopt.cpp
        src/main.cpp
        )

target_link_libraries(pktvisord
        PRIVATE pktvisorcore
        )

add_executable(tests
        tests/main.cpp
        tests/test_parse_pcap.cpp
        tests/test_sketches.cpp
        tests/test_utils.cpp
        )

if (MMDB_ENABLE)
    target_sources(tests
            PUBLIC
            tests/test_geolite2.cpp
        )
endif()

target_include_directories(tests SYSTEM
        PRIVATE ${CMAKE_SOURCE_DIR}/3rd/datasketches
        PRIVATE "${CMAKE_SOURCE_DIR}/3rd/catch"
        )

target_include_directories(tests
        PRIVATE "${CMAKE_SOURCE_DIR}/tests"
        PRIVATE "${CMAKE_SOURCE_DIR}/src"
        )

target_link_libraries(tests
        PRIVATE pktvisorcore
        )

include_directories(${CMAKE_CURRENT_BINARY_DIR})
configure_file(src/config.h.in config.h @ONLY)
