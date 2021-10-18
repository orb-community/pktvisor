message(STATUS "Handler Module: Mock (dynamic)")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_plugin(VisorHandlerMock
        ${CMAKE_CURRENT_BINARY_DIR}
        MockHandler.conf
        MockHandlerModulePlugin.cpp
        MockStreamHandler.cpp)
add_library(Visor::Handler::Mock ALIAS VisorHandlerMock)

target_include_directories(VisorHandlerMock
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorHandlerMock
        PUBLIC
        Visor::Input::Mock
        )
