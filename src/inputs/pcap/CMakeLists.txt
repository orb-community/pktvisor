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
        ${VIZER_VENDOR_DIR}
        ${LIBPCPP_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/src # FIXME ?
        ${VIZER_VENDOR_DIR}/datasketches
        ${VIZER_VENDOR_DIR}/datasketches/datasketches
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
        vizer-core
        )

set(VIZER_STATIC_PLUGINS ${VIZER_STATIC_PLUGINS} PcapInput PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-input-pcap
        tests/main.cpp
        tests/test_parse_pcap.cpp
        tests/test_utils.cpp
        )

target_include_directories(unit-tests-input-pcap
        PRIVATE
        ${VIZER_VENDOR_DIR}
        ${VIZER_VENDOR_DIR}/catch
        ${CMAKE_CURRENT_SOURCE_DIR}
        #
        ${LIBPCPP_INCLUDE_DIRS}  # pcpp
        ${VIZER_VENDOR_DIR}/datasketches
        ${VIZER_VENDOR_DIR}/datasketches/datasketches
        )

target_link_libraries(unit-tests-input-pcap
        PRIVATE vizer-core PcapInput
        )

if (APPLE)
    target_link_libraries(unit-tests-input-pcap
            PRIVATE
            "-L${LIBPCPP_LIBRARY_DIRS}"
            ${LIBPCPP_LIBRARIES}
            "-framework CoreFoundation"
            "-framework SystemConfiguration"
            )
else ()
    target_link_libraries(unit-tests-input-pcap
            PRIVATE
            ${LIBPCPP_LDFLAGS}
            ${LIBPCPP_LIBRARIES}
            )
endif ()
