message(STATUS "Input Module: Net Probe")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorInputNetProbe
        ${CMAKE_CURRENT_BINARY_DIR}
        NetProbeInput.conf
        NetProbeInputModulePlugin.cpp
        NetProbeInputStream.cpp
        PingProbe.cpp
        )
add_library(Visor::Input::NetProbe ALIAS VisorInputNetProbe)

target_include_directories(VisorInputNetProbe
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorInputNetProbe
        PUBLIC
        Visor::Core
        Visor::Input::Pcap
        ${CONAN_LIBS_LIBUV}
        ${CONAN_LIBS_UVW}
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Input::NetProbe PARENT_SCOPE)

## TEST SUITE
#add_executable(unit-tests-input-flow
#        tests/main.cpp
#        tests/test_flow.cpp
#        )
#
#target_link_libraries(unit-tests-input-flow
#        PRIVATE Visor::Input::Flow
#        )
#
#add_test(NAME unit-tests-input-flow
#        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
#        COMMAND unit-tests-input-flow
#        )