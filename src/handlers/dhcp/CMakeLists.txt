message(STATUS "Handler Module: DHCP")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerDhcp
        ${CMAKE_CURRENT_BINARY_DIR}
        DhcpHandler.conf
        DhcpHandlerModulePlugin.cpp
        DhcpStreamHandler.cpp)
add_library(Visor::Handler::Dhcp ALIAS VisorHandlerDhcp)

target_include_directories(VisorHandlerDhcp
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

target_link_libraries(VisorHandlerDhcp
        PUBLIC
        Visor::Lib::Transaction
        Visor::Input::Pcap)

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Dhcp PARENT_SCOPE)


## TEST SUITE
add_executable(unit-tests-handler-dhcp
        tests/test_dhcp_layer.cpp
        tests/test_json_schema.cpp)

target_link_libraries(unit-tests-handler-dhcp
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Dhcp
        Visor::Lib::Test)

add_test(NAME unit-tests-handler-dhcp
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-dhcp)
