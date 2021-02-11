message(STATUS "Input Module: Pcap")

pkg_check_modules(LIBPCPP REQUIRED PcapPlusPlus)

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VizerInputPcap ${CMAKE_CURRENT_BINARY_DIR}
        PcapInput.conf
        PcapInputModulePlugin.cpp
        PcapInputStream.cpp
        utils.cpp
        )
add_library(Vizer::Input::Pcap ALIAS VizerInputPcap)

target_include_directories(VizerInputPcap
        PUBLIC
        ${LIBPCPP_INCLUDE_DIRS}
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

if (APPLE)
    target_link_libraries(VizerInputPcap
            PRIVATE
            "-L${LIBPCPP_LIBRARY_DIRS}"
            ${LIBPCPP_LIBRARIES}
            "-framework CoreFoundation"
            "-framework SystemConfiguration"
            )
else ()
    target_link_libraries(VizerInputPcap
            PRIVATE
            ${LIBPCPP_LDFLAGS}
            ${LIBPCPP_LIBRARIES}
            )
endif ()

target_link_libraries(VizerInputPcap
        PUBLIC
        Vizer::Core
        )

set(VIZER_STATIC_PLUGINS ${VIZER_STATIC_PLUGINS} VizerInputPcap PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-input-pcap
        tests/main.cpp
        tests/test_parse_pcap.cpp
        tests/test_utils.cpp
        )

target_link_libraries(unit-tests-input-pcap
        PRIVATE Vizer::Input::Pcap
        )

