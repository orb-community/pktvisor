message(STATUS "Handler Module: DNS v1")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerDnsV1
        ${CMAKE_CURRENT_BINARY_DIR}
        DnsHandler.conf
        DnsHandlerModulePlugin.cpp
        DnsStreamHandler.cpp
        )
add_library(Visor::Handler::Dns::V1 ALIAS VisorHandlerDnsV1)

target_include_directories(VisorHandlerDnsV1
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerDnsV1
        PUBLIC
        Visor::Dns
        Visor::Input::Pcap
        Visor::Input::Dnstap
        Visor::Input::Mock
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Dns::V1 PARENT_SCOPE)

add_subdirectory(tests)