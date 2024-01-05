message(STATUS "Handler Module: Net Probe")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerNetProbe
        ${CMAKE_CURRENT_BINARY_DIR}
        NetProbeHandler.conf
        NetProbeHandlerModulePlugin.cpp
        NetProbeStreamHandler.cpp
        )
add_library(Visor::Handler::NetProbe ALIAS VisorHandlerNetProbe)

target_include_directories(VisorHandlerNetProbe
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerNetProbe
        PUBLIC
        Visor::Lib::Transaction
        Visor::Input::NetProbe
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::NetProbe PARENT_SCOPE)

add_subdirectory(tests)