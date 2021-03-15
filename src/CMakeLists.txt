
message(STATUS "vizer-core")

find_package(Corrade REQUIRED PluginManager)

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

add_library(vizer-core
        AbstractPlugin.cpp
        InputModulePlugin.cpp
        HandlerModulePlugin.cpp
        GeoDB.cpp
        CoreServer.cpp
        )
add_library(Vizer::Core ALIAS vizer-core)

target_include_directories(vizer-core
        PRIVATE
        ${CMAKE_BINARY_DIR}/src # Vizer::Core config.h
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(vizer-core
        PUBLIC
        datasketches
        rng
        timer
        maxminddb
        ${CONAN_LIBS_CORRADE}
        ${CONAN_LIBS_SPDLOG}
        ${CONAN_LIBS_FMT}
        ${VIZER_STATIC_PLUGINS}
        )

configure_file(vizer_config.h.in vizer_config.h @ONLY)

add_subdirectory(inputs)
add_subdirectory(handlers)

set(VIZER_STATIC_PLUGINS ${VIZER_STATIC_PLUGINS} PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-vizor-core
        tests/main.cpp
        tests/test_sketches.cpp
        tests/test_metrics.cpp
        tests/test_geoip.cpp
        )

target_include_directories(unit-tests-vizor-core
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
        )

target_link_libraries(unit-tests-vizor-core PRIVATE Vizer::Core)

add_test(NAME unit-tests-vizor-core
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/tests
        COMMAND unit-tests-vizor-core
        )