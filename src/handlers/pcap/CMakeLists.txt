message(STATUS "Handler Module: Pcap")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerPcap
        ${CMAKE_CURRENT_BINARY_DIR}
        PcapHandler.conf
        PcapHandlerModulePlugin.cpp
        PcapStreamHandler.cpp)
add_library(Visor::Handler::Pcap ALIAS VisorHandlerPcap)

target_include_directories(VisorHandlerPcap
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerPcap
        PUBLIC
        Visor::Input::Pcap
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Pcap PARENT_SCOPE)

add_subdirectory(tests)