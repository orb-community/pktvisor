add_executable(pktvisor-pcap
        main.cpp
        )

target_include_directories(pktvisor-pcap
        PRIVATE
        ${VIZER_VENDOR_DIR}
        ${VIZER_VENDOR_DIR}/datasketches
        ${VIZER_VENDOR_DIR}/datasketches/datasketches
        ${CMAKE_SOURCE_DIR}/src
        ${LIBPCPP_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/src/inputs/pcap # FIXME - dependency on pcap
        ${CMAKE_BINARY_DIR}/src # FIXME config.h
        )

target_link_libraries(pktvisor-pcap PRIVATE vizer-core)
