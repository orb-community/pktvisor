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
add_library(Vizer::Core ALIAS vizer-core)

target_include_directories(vizer-core
        PUBLIC
        ${LIBMMDB_INCLUDE_DIRS}
        )

target_link_libraries(vizer-core
        PUBLIC
        datasketches
        rng
        ${LIBMMDB_LDFLAGS}
        ${LIBMMDB_LIBRARIES}
        )

configure_file(config.h.in config.h @ONLY)

add_subdirectory(inputs)
add_subdirectory(handlers)

set(VIZER_STATIC_PLUGINS ${VIZER_STATIC_PLUGINS} PARENT_SCOPE)

## TEST SUITE
add_executable(vizor-core-tests
        tests/main.cpp
        tests/test_sketches.cpp
        tests/test_metrics.cpp
        tests/test_geoip.cpp
        )

target_include_directories(vizor-core-tests
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
        )

target_link_libraries(vizor-core-tests PRIVATE Vizer::Core)
