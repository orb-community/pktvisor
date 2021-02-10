cmake_minimum_required(VERSION 3.13)

message(STATUS "vizer-core")

find_package(Corrade REQUIRED PluginManager)
pkg_check_modules(LIBMMDB REQUIRED libmaxminddb)

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

add_library(vizer-core
        AbstractPlugin.cpp
        InputModulePlugin.cpp
        HandlerModulePlugin.cpp
        GeoDB.cpp
        )

target_include_directories(vizer-core
        PRIVATE
        ${VIZER_VENDOR_DIR}
        # FIXME
        ${VIZER_VENDOR_DIR}/datasketches
        ${VIZER_VENDOR_DIR}/datasketches/datasketches
        #
        PUBLIC ${LIBMMDB_INCLUDE_DIRS}
        PUBLIC ${CONAN_INCLUDE_DIRS}
        )

target_link_libraries(vizer-core
        PRIVATE
        ${LIBMMDB_LDFLAGS}
        ${LIBMMDB_LIBRARIES}
        PUBLIC ${CONAN_LIBS}
        )

configure_file(config.h.in config.h @ONLY)

add_subdirectory(inputs/pcap)

add_subdirectory(handlers/net)
add_subdirectory(handlers/dns)

set(VIZER_STATIC_PLUGINS ${VIZER_STATIC_PLUGINS} PARENT_SCOPE)

## TEST SUITE
add_executable(vizor-core-tests
        tests/main.cpp
        tests/test_sketches.cpp
        tests/test_metrics.cpp
        tests/test_geoip.cpp
        )

target_include_directories(vizor-core-tests
        PRIVATE
        ${VIZER_VENDOR_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        # FIXME
        ${VIZER_VENDOR_DIR}/datasketches
        ${VIZER_VENDOR_DIR}/datasketches/datasketches
        #
        )

target_link_libraries(vizor-core-tests
        PRIVATE vizer-core
        )
