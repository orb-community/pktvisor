message(STATUS "Handler Module: DNS Xact")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerDnsXact
        ${CMAKE_CURRENT_BINARY_DIR}
        DnsXactHandler.conf
        DnsXactHandlerModulePlugin.cpp
        DnsXactStreamHandler.cpp
        querypairmgr.cpp
        )
add_library(Visor::Handler::Dns::Xact ALIAS VisorHandlerDnsXact)

target_include_directories(VisorHandlerDnsXact
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerDnsXact
        PUBLIC
        ${CONAN_LIBS_ROBIN-HOOD-HASHING}
        Visor::Dns
        Visor::Input::Pcap
        Visor::Input::Dnstap
        Visor::Input::Mock
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Dns::Xact PARENT_SCOPE)

add_subdirectory(tests)