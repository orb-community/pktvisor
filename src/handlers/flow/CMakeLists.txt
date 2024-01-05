message(STATUS "Handler Module: Flow")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerFlow
        ${CMAKE_CURRENT_BINARY_DIR}
        FlowHandler.conf
        FlowHandlerModulePlugin.cpp
        FlowStreamHandler.cpp)
add_library(Visor::Handler::Flow ALIAS VisorHandlerFlow)

target_include_directories(VisorHandlerFlow
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerFlow
        PUBLIC
        Visor::Lib::Utils
        Visor::Input::Mock
        Visor::Input::Flow
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Flow PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-handler-flow test_flows.cpp)

target_link_libraries(unit-tests-handler-flow
        PRIVATE
        Visor::Handler::Flow
        Visor::Lib::Test)

add_test(NAME unit-tests-handler-flow
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-flow)