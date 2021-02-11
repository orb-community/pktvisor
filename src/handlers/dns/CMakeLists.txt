message(STATUS "Handler Module: DNS")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VizerHandlerDns
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
add_library(Vizer::Handler::Dns ALIAS VizerHandlerDns)

target_include_directories(VizerHandlerDns
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VizerHandlerDns
        PUBLIC
        Vizer::Input::Pcap
        )

set(VIZER_STATIC_PLUGINS ${VIZER_STATIC_PLUGINS} VizerHandlerDns PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-handler-dns
        tests/main.cpp
        tests/test_dns.cpp
        tests/test_dns_layer.cpp
        )

target_link_libraries(unit-tests-handler-dns PRIVATE Vizer::Handler::Dns)

