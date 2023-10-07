message(STATUS "Handler Module: DNS v2")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerDnsV2
        ${CMAKE_CURRENT_BINARY_DIR}
        DnsHandler.conf
        DnsHandlerModulePlugin.cpp
        DnsStreamHandler.cpp
        )
add_library(Visor::Handler::Dns::V2 ALIAS VisorHandlerDnsV2)

target_include_directories(VisorHandlerDnsV2
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerDnsV2
        PUBLIC
        Visor::Lib::Dns
        Visor::Lib::Transaction
        Visor::Input::Pcap
        Visor::Input::Dnstap
        Visor::Input::Mock
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Dns::V2 PARENT_SCOPE)

add_subdirectory(tests)