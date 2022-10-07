message(STATUS "Handler Module: Input Resources")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerInputResources
        ${CMAKE_CURRENT_BINARY_DIR}
        InputResourcesHandler.conf
        InputResourcesHandlerModulePlugin.cpp
        InputResourcesStreamHandler.cpp
        )
add_library(Visor::Handler::InputResources ALIAS VisorHandlerInputResources)

target_include_directories(VisorHandlerInputResources
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerInputResources
        PUBLIC
        Visor::Input::Pcap
        Visor::Input::Dnstap
        Visor::Input::Mock
        Visor::Input::Flow
        Visor::Input::NetProbe
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::InputResources PARENT_SCOPE)

add_subdirectory(tests)