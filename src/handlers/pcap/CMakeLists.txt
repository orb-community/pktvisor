message(STATUS "Handler Module: Pcap v1")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerPcapV1
        ${CMAKE_CURRENT_BINARY_DIR}
        PcapHandler.conf
        PcapHandlerModulePlugin.cpp
        PcapStreamHandler.cpp)
add_library(Visor::Handler::Pcap::V1 ALIAS VisorHandlerPcapV1)

target_include_directories(VisorHandlerPcapV1
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerPcapV1
        PUBLIC
        Visor::Input::Pcap
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Pcap::V1 PARENT_SCOPE)

add_subdirectory(tests)