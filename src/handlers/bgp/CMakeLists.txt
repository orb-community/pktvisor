message(STATUS "Handler Module: BGP")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerBgp
        ${CMAKE_CURRENT_BINARY_DIR}
        BgpHandler.conf
        BgpHandlerModulePlugin.cpp
        BgpStreamHandler.cpp)
add_library(Visor::Handler::Bgp ALIAS VisorHandlerBgp)

target_include_directories(VisorHandlerBgp
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerBgp
        PUBLIC
        Visor::Input::Pcap
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Bgp PARENT_SCOPE)

add_subdirectory(tests)