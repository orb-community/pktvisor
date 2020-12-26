message(STATUS "Handler Module: Net")

add_library(pktvisor-handler-net
        NetHandlerModuleDesc.cpp
        NetStreamHandler.cpp
        )

target_include_directories(pktvisor-handler-net
        PUBLIC
        ${CMAKE_SOURCE_DIR}/3rd
        ${CMAKE_SOURCE_DIR}/src-m
        )

target_link_libraries(pktvisord-m
        PRIVATE pktvisorcore-m
        pktvisor-handler-net
        )