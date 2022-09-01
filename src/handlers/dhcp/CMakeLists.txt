message(STATUS "Handler Module: DHCP")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerDhcpV1
        ${CMAKE_CURRENT_BINARY_DIR}
        DhcpHandler.conf
        DhcpHandlerModulePlugin.cpp
        DhcpStreamHandler.cpp)
add_library(Visor::Handler::Dhcp::V1 ALIAS VisorHandlerDhcpV1)

target_include_directories(VisorHandlerDhcpV1
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerDhcpV1
        PUBLIC
        Visor::Input::Pcap
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Dhcp::V1 PARENT_SCOPE)

add_subdirectory(tests)