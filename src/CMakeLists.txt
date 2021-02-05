cmake_minimum_required(VERSION 3.13)

message(STATUS "Modular support will build")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/3rd/corrade/modules")

find_package(Corrade REQUIRED PluginManager)
pkg_check_modules(LIBMMDB REQUIRED libmaxminddb)

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

add_library(pktvisorcore
        AbstractPlugin.cpp
        InputModulePlugin.cpp
        HandlerModulePlugin.cpp
        GeoDB.cpp
        )

target_include_directories(pktvisorcore
        PRIVATE
        ${PKTVISOR_VENDOR_DIR}
        # FIXME
        ${PKTVISOR_VENDOR_DIR}/datasketches
        ${PKTVISOR_VENDOR_DIR}/datasketches/datasketches
        #
        PUBLIC ${LIBMMDB_INCLUDE_DIRS}
        ${CORRADE_INCLUDE_DIR}
        ${Corrade_BINARY_DIR}/src # FIXME configure.h, probably not right
        )

target_link_libraries(pktvisorcore
        PRIVATE
        ${LIBMMDB_LDFLAGS}
        ${LIBMMDB_LIBRARIES}
        Corrade::PluginManager
        )

configure_file(config.h.in config.h @ONLY)

add_subdirectory(inputs/pcap)

add_subdirectory(handlers/net)
add_subdirectory(handlers/dns)

set(PKTVISOR_STATIC_PLUGINS ${PKTVISOR_STATIC_PLUGINS} PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-core
        tests/main.cpp
        tests/test_sketches.cpp
        tests/test_metrics.cpp
        tests/test_geoip.cpp
        )

target_include_directories(unit-tests-core
        PRIVATE
        ${PKTVISOR_VENDOR_DIR}
        ${PKTVISOR_VENDOR_DIR}/catch
        ${CMAKE_CURRENT_SOURCE_DIR}
        # FIXME
        ${PKTVISOR_VENDOR_DIR}/datasketches
        ${PKTVISOR_VENDOR_DIR}/datasketches/datasketches
        #
        )

target_link_libraries(unit-tests-core
        PRIVATE pktvisorcore
        )
