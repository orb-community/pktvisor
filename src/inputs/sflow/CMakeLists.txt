message(STATUS "Input Module: Sflow")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorInputSflow ${CMAKE_CURRENT_BINARY_DIR}
        SflowInput.conf
        SflowInputModulePlugin.cpp
        SflowInputStream.cpp
        )
add_library(Visor::Input::Sflow ALIAS VisorInputSflow)

target_include_directories(VisorInputSflow
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorInputSflow
        PUBLIC
        sflow
        Visor::Core
        ${CONAN_LIBS_LIBUV}
        ${CONAN_LIBS_UVW}
        ${CONAN_LIBS_PCAPPLUSPLUS}
        ${CONAN_LIBS_LIBPCAP}
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Input::Sflow PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-input-sflow
        tests/main.cpp
        tests/test_sflow.cpp
        )

target_link_libraries(unit-tests-input-sflow
        PRIVATE Visor::Input::Sflow
        )

add_test(NAME unit-tests-input-sflow
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
        COMMAND unit-tests-input-sflow
        )