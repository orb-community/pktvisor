
message(STATUS "visor-core")

find_package(Corrade REQUIRED PluginManager)

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

add_library(visor-core
        AbstractPlugin.cpp
        InputModulePlugin.cpp
        HandlerModulePlugin.cpp
        GeoDB.cpp
        CoreServer.cpp
        CoreManagers.cpp
        Metrics.cpp
        Policies.cpp
        Taps.cpp)
add_library(Visor::Core ALIAS visor-core)

target_include_directories(visor-core
        PRIVATE
        ${CMAKE_BINARY_DIR}/src # Visor::Core config.h
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(visor-core
        PUBLIC
        datasketches
        rng
        timer
        maxminddb
        ${CONAN_LIBS_CORRADE}
        ${CONAN_LIBS_SPDLOG}
        ${CONAN_LIBS_FMT}
        ${CONAN_LIBS_YAML-CPP}
        ${VISOR_STATIC_PLUGINS}
        )

configure_file(visor_config.h.in visor_config.h @ONLY)

add_subdirectory(inputs)
add_subdirectory(handlers)

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-vizor-core
        tests/main.cpp
        tests/test_sketches.cpp
        tests/test_metrics.cpp
        tests/test_geoip.cpp
        tests/test_taps.cpp
        tests/test_policies.cpp
        )

target_include_directories(unit-tests-vizor-core
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
        )

target_link_libraries(unit-tests-vizor-core PRIVATE Visor::Core ${VISOR_STATIC_PLUGINS})

add_test(NAME unit-tests-vizor-core
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
        COMMAND unit-tests-vizor-core
        )