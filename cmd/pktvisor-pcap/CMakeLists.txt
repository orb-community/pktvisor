add_executable(pktvisor-pcap
        ${PKTVISOR_VENDOR_DIR}/docopt/docopt.cpp
        main.cpp
        )

target_include_directories(pktvisor-pcap
        PRIVATE
        ${PKTVISOR_VENDOR_DIR}
        ${CORRADE_INCLUDE_DIR}
        ${PKTVISOR_VENDOR_DIR}/datasketches
        ${PKTVISOR_VENDOR_DIR}/datasketches/datasketches
        ${CMAKE_SOURCE_DIR}/src
        ${LIBPCPP_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/src/inputs/pcap # FIXME - dependency on pcap
        ${Corrade_BINARY_DIR}/src # FIXME configure.h, probably not right
        ${CMAKE_BINARY_DIR}/src # FIXME config.h
        )

target_link_libraries(pktvisor-pcap PRIVATE pktvisorcore ${PKTVISOR_STATIC_PLUGINS})
