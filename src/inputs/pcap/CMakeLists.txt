message(STATUS "Input Module: Pcap")

pkg_check_modules(LIBPCPP REQUIRED PcapPlusPlus)

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(PcapInput ${CMAKE_CURRENT_BINARY_DIR}
        PcapInput.conf
        PcapInputModulePlugin.cpp
        PcapInputStream.cpp
        utils.cpp
        )

target_include_directories(PcapInput
        PRIVATE
        ${PKTVISOR_VENDOR_DIR}
        ${LIBPCPP_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/src # FIXME ?
        ${CORRADE_INCLUDE_DIR}
        ${PKTVISOR_VENDOR_DIR}/datasketches
        ${PKTVISOR_VENDOR_DIR}/datasketches/datasketches
        ${Corrade_BINARY_DIR}/src # FIXME configure.h, probably not right
        )

if (APPLE)
    target_link_libraries(PcapInput
            PRIVATE
            "-L${LIBPCPP_LIBRARY_DIRS}"
            ${LIBPCPP_LIBRARIES}
            "-framework CoreFoundation"
            "-framework SystemConfiguration"
            )
else ()
    target_link_libraries(PcapInput
            PRIVATE
            ${LIBPCPP_LDFLAGS}
            ${LIBPCPP_LIBRARIES}
            )
endif ()

target_link_libraries(PcapInput
        PRIVATE
        pktvisorcore
        )

set(PKTVISOR_STATIC_PLUGINS ${PKTVISOR_STATIC_PLUGINS} PcapInput PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-input-pcap
        tests/main.cpp
        tests/test_parse_pcap.cpp
        tests/test_utils.cpp
        )

target_include_directories(unit-tests-input-pcap SYSTEM
        PRIVATE ${CMAKE_SOURCE_DIR}/3rd/datasketches
        PRIVATE "${CMAKE_SOURCE_DIR}/3rd/catch"
        )

target_include_directories(unit-tests-input-pcap
        PRIVATE "${CMAKE_SOURCE_DIR}/tests"
        PRIVATE "${CMAKE_SOURCE_DIR}/src"
        )

target_link_libraries(unit-tests-input-pcap
        PRIVATE pktvisorcore
        )
