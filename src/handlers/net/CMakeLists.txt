message(STATUS "Handler Module: Net")

pkg_check_modules(LIBPCPP REQUIRED PcapPlusPlus)

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VizerHandlerNet
        ${CMAKE_CURRENT_BINARY_DIR}
        NetHandler.conf
        NetHandlerModulePlugin.cpp
        NetStreamHandler.cpp)
add_library(Vizer::Handler::Net ALIAS VizerHandlerNet)

target_include_directories(VizerHandlerNet
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VizerHandlerNet
        PUBLIC
        Vizer::Input::Pcap
        )

set(VIZER_STATIC_PLUGINS ${VIZER_STATIC_PLUGINS} VizerHandlerNet PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-handler-net
        tests/main.cpp
        tests/test_net_layer.cpp
        )

target_link_libraries(unit-tests-handler-net PRIVATE Vizer::Handler::Net)
