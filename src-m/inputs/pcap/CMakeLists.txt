message(STATUS "Input Module: Pcap")

pkg_check_modules(LIBPCPP REQUIRED PcapPlusPlus)

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(PcapInput ${CMAKE_CURRENT_BINARY_DIR} PcapInput.conf PcapInputModulePlugin.cpp PcapInputStream.cpp)

target_include_directories(PcapInput
        PRIVATE
        ${PKTVISOR_VENDOR_DIR}
        ${LIBPCPP_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/src-m # FIXME ?
        ${CORRADE_INCLUDE_DIR}
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
        pktvisorcore-m
        )
set(PKTVISOR_STATIC_PLUGINS ${PKTVISOR_STATIC_PLUGINS} PcapInput PARENT_SCOPE)
