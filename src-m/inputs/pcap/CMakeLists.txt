message(STATUS "Input Module: Pcap")

add_library(pktvisor-input-pcap
        PcapInputModuleDesc.cpp
        PcapStreamInput.cpp
        )

target_include_directories(pktvisor-input-pcap
        PUBLIC
        ${CMAKE_SOURCE_DIR}/3rd
        ${CMAKE_SOURCE_DIR}/src-m
        )

target_link_libraries(pktvisord-m
        PRIVATE pktvisorcore-m
        pktvisor-input-pcap
        )