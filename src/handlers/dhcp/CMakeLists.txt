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
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerDhcp
        PUBLIC
        Visor::Input::Pcap
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Dhcp PARENT_SCOPE)

add_subdirectory(tests)