message(STATUS "Handler Module: DNS Xact")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerDnsXact
        ${CMAKE_CURRENT_BINARY_DIR}
        DnsXactHandler.conf
        DnsXactHandlerModulePlugin.cpp
        DnsXactStreamHandler.cpp
        querypairmgr.cpp
        )
add_library(Visor::Handler::DnsXact ALIAS VisorHandlerDnsXact)

target_include_directories(VisorHandlerDnsXact
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerDnsXact
        PUBLIC
        Visor::Dns
        ${CONAN_LIBS_ROBIN-HOOD-HASHING}
        Visor::Input::Pcap
        Visor::Input::Dnstap
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::DnsXact PARENT_SCOPE)

add_subdirectory(tests)