message(STATUS "Input Module: Pcap")

pkg_check_modules(LIBPCPP REQUIRED PcapPlusPlus)

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(PcapInput ${CMAKE_CURRENT_BINARY_DIR} PcapInput.conf PcapStreamInputDesc.cpp PcapStreamInput.cpp)

target_include_directories(PcapInput
        PRIVATE
        ${PKTVISOR_VENDOR_DIR}
        ${LIBPCPP_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/src-m # FIXME ?
        ${CORRADE_INCLUDE_DIR}
        ${Corrade_BINARY_DIR}/src # FIXME configure.h, probably not right
        )

# FIXME should this happen here?
target_link_libraries(pktvisorcore-m
        PRIVATE
        ${LIBPCPP_LDFLAGS}
        ${LIBPCPP_LIBRARIES}}
        PcapInput
        Corrade::PluginManager)
