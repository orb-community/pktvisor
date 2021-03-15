message(STATUS "Input Module: Pcap")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(VizerInputPcap ${CMAKE_CURRENT_BINARY_DIR}
        PcapInput.conf
        PcapInputModulePlugin.cpp
        PcapInputStream.cpp
        afpacket.cpp
        utils.cpp
        )
add_library(Vizer::Input::Pcap ALIAS VizerInputPcap)

target_include_directories(VizerInputPcap
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VizerInputPcap
        PUBLIC
        ${CONAN_LIBS_PCAPPLUSPLUS}
        ${CONAN_LIBS_LIBPCAP}
        Vizer::Core
        )

set(VIZER_STATIC_PLUGINS ${VIZER_STATIC_PLUGINS} Vizer::Input::Pcap PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-input-pcap
        tests/main.cpp
        tests/test_parse_pcap.cpp
        tests/test_utils.cpp
        )

target_link_libraries(unit-tests-input-pcap
        PRIVATE Vizer::Input::Pcap
        )

add_test(NAME unit-tests-input-pcap
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/tests
        COMMAND unit-tests-input-pcap
        )
