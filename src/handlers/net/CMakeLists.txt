message(STATUS "Handler Module: Net")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerNet
        ${CMAKE_CURRENT_BINARY_DIR}
        NetHandler.conf
        NetHandlerModulePlugin.cpp
        NetStreamHandler.cpp)
add_library(Visor::Handler::Net ALIAS VisorHandlerNet)

target_include_directories(VisorHandlerNet
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerNet
        PUBLIC
        Visor::Input::Pcap
        Visor::Input::Mock
        Visor::Input::Dnstap
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Net PARENT_SCOPE)

add_subdirectory(tests)