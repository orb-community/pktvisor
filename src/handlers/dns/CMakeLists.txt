message(STATUS "Handler Module: DNS")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerDns
        ${CMAKE_CURRENT_BINARY_DIR}
        DnsHandler.conf
        DnsHandlerModulePlugin.cpp
        DnsStreamHandler.cpp
        dns.cpp
        querypairmgr.cpp
        # DnsLayer
        DnsLayer.cpp
        DnsResource.cpp
        DnsResourceData.cpp
        )
add_library(Visor::Handler::Dns ALIAS VisorHandlerDns)

target_include_directories(VisorHandlerDns
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerDns
        PUBLIC
        Visor::Input::Pcap
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Dns PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-handler-dns
        tests/main.cpp
        tests/test_dns.cpp
        tests/test_dns_layer.cpp
        )

target_link_libraries(unit-tests-handler-dns PRIVATE Visor::Handler::Dns)

add_test(NAME unit-tests-handler-dns
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/tests
        COMMAND unit-tests-handler-dns
        )