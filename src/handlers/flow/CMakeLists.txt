message(STATUS "Handler Module: Flow v1")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VisorHandlerFlowV1
        ${CMAKE_CURRENT_BINARY_DIR}
        FlowHandler.conf
        FlowHandlerModulePlugin.cpp
        FlowStreamHandler.cpp)
add_library(Visor::Handler::Flow::V1 ALIAS VisorHandlerFlowV1)

target_include_directories(VisorHandlerFlowV1
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerFlowV1
        PUBLIC
        Visor::Input::Mock
        Visor::Input::Flow
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Handler::Flow::V1 PARENT_SCOPE)

add_subdirectory(tests)