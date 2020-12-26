message(STATUS "Handler Module: DNS")

add_library(pktvisor-handler-dns
        DnsStreamHandler.cpp
        )

target_include_directories(pktvisor-handler-dns
        PUBLIC
        ${CMAKE_SOURCE_DIR}/3rd
        ${CMAKE_SOURCE_DIR}/src-m
        )
