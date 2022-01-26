message(STATUS "Input Module: Sflow")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorInputSflow ${CMAKE_CURRENT_BINARY_DIR}
        SflowInput.conf
        SflowInputModulePlugin.cpp
        SflowInputStream.cpp
        )
add_library(Visor::Input::Sflow ALIAS VisorInputSflow)

target_include_directories(VisorInputSflow
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorInputSflow
        PUBLIC
        sflow
        Visor::Core
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Input::Sflow PARENT_SCOPE)