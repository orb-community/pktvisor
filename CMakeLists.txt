cmake_minimum_required(VERSION 3.13)
project(pktvisor)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# this is the source of truth for version, which will be written to config.h include file.
project(pktvisord VERSION 3.1.0)
set(PKTVISOR_VERSION_NUM ${PROJECT_VERSION})
set(PKTVISOR_VERSION "pktvisor ${PROJECT_VERSION}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
add_compile_options(-Wall)

set(PKTVISOR_VENDOR_DIR "${CMAKE_SOURCE_DIR}/3rd")

find_package(PkgConfig)

include(sanitizer)

# Corrade depedency
set(WITH_TESTSUITE OFF CACHE BOOL "" FORCE)
set(WITH_INTERCONNECT OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC ON CACHE BOOL "" FORCE)
add_subdirectory(${CMAKE_SOURCE_DIR}/3rd/corrade EXCLUDE_FROM_ALL)

set(PKTVISOR_STATIC_PLUGINS)
add_subdirectory(src)
add_subdirectory(cmd/pktvisord)
add_subdirectory(cmd/pktvisor-pcap)

# INTEGRATION TESTING
#enable_testing()
#
#add_test(NAME pktvisor-units
#        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
#        COMMAND ${CMAKE_BINARY_DIR}/unit-tests
#        )
#
#add_test(NAME pktvisor-ftest-ipv4-udp
#        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
#        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv4_udp.json -- -H 127.0.0.1/32 fixtures/dns_ipv4_udp.pcap
#        )
#add_test(NAME pktvisor-ftest-ipv4-tcp
#        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
#        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv4_tcp.json -- -H 127.0.0.1/32 fixtures/dns_ipv4_tcp.pcap
#        )
#add_test(NAME pktvisor-ftest-ipv6-udp
#        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
#        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv6_udp.json -- -H 127.0.0.1/32 fixtures/dns_ipv6_udp.pcap
#        )
#add_test(NAME pktvisor-ftest-ipv6-tcp
#        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
#        COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv6_tcp.json -- -H 127.0.0.1/32 fixtures/dns_ipv6_tcp.pcap
#        )
#
#if (MMDB_ENABLE)
#    add_test(NAME pktvisor-ftest-ipv4-udp-geo
#            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
#            COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv4_udp_geo.json -- -H 127.0.0.1/32 --geo-city fixtures/GeoIP2-City-Test.mmdb --geo-asn fixtures/GeoIP2-ISP-Test.mmdb fixtures/dns_ipv4_udp.pcap
#            )
#    add_test(NAME pktvisor-ftest-ipv4-tcp-geo
#            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
#            COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv4_tcp_geo.json -- -H 127.0.0.1/32 --geo-city fixtures/GeoIP2-City-Test.mmdb --geo-asn fixtures/GeoIP2-ISP-Test.mmdb fixtures/dns_ipv4_udp.pcap
#            )
#    add_test(NAME pktvisor-ftest-ipv6-udp-geo
#            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
#            COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv6_udp_geo.json -- -H 127.0.0.1/32 --geo-city fixtures/GeoIP2-City-Test.mmdb --geo-asn fixtures/GeoIP2-ISP-Test.mmdb fixtures/dns_ipv6_udp.pcap
#            )
#    add_test(NAME pktvisor-ftest-ipv6-tcp-geo
#            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
#            COMMAND ${CMAKE_SOURCE_DIR}/tests/integration.sh ${CMAKE_BINARY_DIR}/pktvisord output-templates/dns_ipv6_tcp_geo.json -- -H 127.0.0.1/32 --geo-city fixtures/GeoIP2-City-Test.mmdb --geo-asn fixtures/GeoIP2-ISP-Test.mmdb fixtures/dns_ipv6_tcp.pcap
#            )
#endif ()
#
#add_test(NAME external-tests
#        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
#        COMMAND ${CMAKE_SOURCE_DIR}/tests/external.sh ${CMAKE_BINARY_DIR}/pktvisord
#        )
