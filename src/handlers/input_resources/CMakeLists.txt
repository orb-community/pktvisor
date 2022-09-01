message(STATUS "Handler Module: Input Resources v1")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerInputResourcesV1
        ${CMAKE_CURRENT_BINARY_DIR}
        InputResourcesHandler.conf
        InputResourcesHandlerModulePlugin.cpp
        InputResourcesStreamHandler.cpp
        )
add_library(Visor::Handler::InputResources::V1 ALIAS VisorHandlerInputResourcesV1)

target_include_directories(VisorHandlerInputResourcesV1
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerInputResourcesV1
        PUBLIC
        Visor::Input::Pcap
        Visor::Input::Dnstap
        Visor::Input::Mock
        Visor::Input::Flow
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::InputResources::V1 PARENT_SCOPE)

add_subdirectory(tests)