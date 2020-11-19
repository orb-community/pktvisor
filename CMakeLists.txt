cmake_minimum_required(VERSION 3.13)
project(pktvisor3)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# this is the source of truth for version, which will be written to config.h include file.
project(pktvisord VERSION 3.0.8)
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
    add_library(geoip
            ${CMAKE_SOURCE_DIR}/src/geoip.cpp
            )
    target_include_directories(geoip
            PUBLIC
            ${LIBMMDB_INCLUDE_DIRS}
            )
    target_link_libraries(geoip
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

add_library(pktvisor-dns
        src/dns/DnsLayer.cpp
        src/dns/DnsResource.cpp
        src/dns/DnsResourceData.cpp
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
            )
    target_link_libraries(pktvisorcore PRIVATE geoip)
endif()

add_executable(pktvisord
        3rd/docopt/docopt.cpp
        src/main.cpp
        )

target_link_libraries(pktvisord
        PRIVATE pktvisorcore pktvisor-dns
        )

add_executable(unit-tests
        tests/main.cpp
        tests/test_parse_pcap.cpp
        tests/test_sketches.cpp
        tests/test_utils.cpp
        tests/test_metrics.cpp
        )

if (MMDB_ENABLE)
    target_sources(unit-tests
            PUBLIC
            tests/test_geoip.cpp
        )
endif()

target_include_directories(unit-tests SYSTEM
        PRIVATE ${CMAKE_SOURCE_DIR}/3rd/datasketches
        PRIVATE "${CMAKE_SOURCE_DIR}/3rd/catch"
        )

target_include_directories(unit-tests
        PRIVATE "${CMAKE_SOURCE_DIR}/tests"
        PRIVATE "${CMAKE_SOURCE_DIR}/src"
        )

target_link_libraries(unit-tests
        PRIVATE pktvisorcore
        )

include_directories(${CMAKE_CURRENT_BINARY_DIR})
configure_file(src/config.h.in config.h @ONLY)

enable_testing()

add_test(NAME pktvisor-units
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
        COMMAND ${CMAKE_BINARY_DIR}/unit-tests
        )

add_test(NAME pktvisor-ftest-ipv4-udp
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv4_udp.json -- -H 127.0.0.1/32 fixtures/dns_ipv4_udp.pcap
        )
add_test(NAME pktvisor-ftest-ipv4-tcp
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv4_tcp.json -- -H 127.0.0.1/32 fixtures/dns_ipv4_tcp.pcap
        )
add_test(NAME pktvisor-ftest-ipv6-udp
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv6_udp.json -- -H 127.0.0.1/32 fixtures/dns_ipv6_udp.pcap
        )
add_test(NAME pktvisor-ftest-ipv6-tcp
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv6_tcp.json -- -H 127.0.0.1/32 fixtures/dns_ipv6_tcp.pcap
        )

if (MMDB_ENABLE)
add_test(NAME pktvisor-ftest-ipv4-udp-geo
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv4_udp_geo.json -- -H 127.0.0.1/32 --geo-city fixtures/GeoIP2-City-Test.mmdb --geo-asn fixtures/GeoIP2-ISP-Test.mmdb fixtures/dns_ipv4_udp.pcap
        )
add_test(NAME pktvisor-ftest-ipv4-tcp-geo
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv4_tcp_geo.json -- -H 127.0.0.1/32 --geo-city fixtures/GeoIP2-City-Test.mmdb --geo-asn fixtures/GeoIP2-ISP-Test.mmdb fixtures/dns_ipv4_udp.pcap
        )
add_test(NAME pktvisor-ftest-ipv6-udp-geo
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv6_udp_geo.json -- -H 127.0.0.1/32 --geo-city fixtures/GeoIP2-City-Test.mmdb --geo-asn fixtures/GeoIP2-ISP-Test.mmdb fixtures/dns_ipv6_udp.pcap
        )
add_test(NAME pktvisor-ftest-ipv6-tcp-geo
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv6_tcp_geo.json -- -H 127.0.0.1/32 --geo-city fixtures/GeoIP2-City-Test.mmdb --geo-asn fixtures/GeoIP2-ISP-Test.mmdb fixtures/dns_ipv6_tcp.pcap
        )
endif()

add_test(NAME external-tests
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
        COMMAND ${CMAKE_SOURCE_DIR}/tests/external.sh ${CMAKE_BINARY_DIR}/pktvisord
        )

