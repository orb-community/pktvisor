message(STATUS "Handler Module: Net")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerNet
        ${CMAKE_CURRENT_BINARY_DIR}
        NetHandler.conf
        NetHandlerModulePlugin.cpp
        NetStreamHandler.cpp)
add_library(Visor::Handler::Net ALIAS VisorHandlerNet)

target_include_directories(VisorHandlerNet
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerNet
        PUBLIC
        Visor::Input::Pcap
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Net PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-handler-net
        tests/main.cpp
        tests/test_net_layer.cpp
        )

target_link_libraries(unit-tests-handler-net PRIVATE Visor::Handler::Net)

add_test(NAME unit-tests-handler-net
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/tests
        COMMAND unit-tests-handler-net
        )