message(STATUS "Handler Module: Net v2")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerNetV2
        ${CMAKE_CURRENT_BINARY_DIR}
        NetHandler.conf
        NetHandlerModulePlugin.cpp
        NetStreamHandler.cpp)
add_library(Visor::Handler::Net::V2 ALIAS VisorHandlerNetV2)

target_include_directories(VisorHandlerNetV2
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerNetV2
        PUBLIC
        Visor::Lib::Tcp
        Visor::Input::Pcap
        Visor::Input::Dnstap
        Visor::Input::Mock
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Net::V2 PARENT_SCOPE)

add_subdirectory(tests)