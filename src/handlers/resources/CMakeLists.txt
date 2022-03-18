message(STATUS "Handler Module: Resources")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerResources
        ${CMAKE_CURRENT_BINARY_DIR}
        ResourcesHandler.conf
        ResourcesHandlerModulePlugin.cpp
        ResourcesStreamHandler.cpp)
add_library(Visor::Handler::Resources ALIAS VisorHandlerResources)

target_include_directories(VisorHandlerResources
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerResources
        PUBLIC
        Visor::Input::Pcap
        Visor::Input::Dnstap
        Visor::Input::Mock
        Visor::Input::Sflow
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Resources PARENT_SCOPE)

add_subdirectory(tests)