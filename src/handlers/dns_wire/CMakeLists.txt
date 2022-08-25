message(STATUS "Handler Module: DNS Wire")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerDnsWire
        ${CMAKE_CURRENT_BINARY_DIR}
        DnsWireHandler.conf
        DnsWireHandlerModulePlugin.cpp
        DnsWireStreamHandler.cpp
        )
add_library(Visor::Handler::Dns::Wire ALIAS VisorHandlerDnsWire)

target_include_directories(VisorHandlerDnsWire
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerDnsWire
        PUBLIC
        ${CONAN_LIBS_ROBIN-HOOD-HASHING}
        Visor::Dns
        Visor::Input::Pcap
        Visor::Input::Dnstap
        Visor::Input::Mock
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Dns::Wire PARENT_SCOPE)

add_subdirectory(tests)