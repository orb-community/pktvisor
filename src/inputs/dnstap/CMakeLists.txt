message(STATUS "Input Module: Dnstap")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorInputDnstap ${CMAKE_CURRENT_BINARY_DIR}
        Dnstap.conf
        DnstapInputModulePlugin.cpp
        DnstapInputStream.cpp
        )
add_library(Visor::Input::Dnstap ALIAS VisorInputDnstap)

target_include_directories(VisorInputDnstap
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorInputDnstap
        PUBLIC
        Visor::Core
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Input::Dnstap PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-input-dnstap
        tests/main.cpp
        tests/test_dnstap.cpp
        )

target_link_libraries(unit-tests-input-dnstap
        PRIVATE Visor::Input::Dnstap
        )

add_test(NAME unit-tests-input-dnstap
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
        COMMAND unit-tests-input-dnstap
        )
