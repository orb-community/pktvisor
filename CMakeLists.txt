cmake_minimum_required(VERSION 3.13)
project(pktvisor3)

set(CMAKE_CXX_STANDARD 17)
add_compile_options(-Wall)

#set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
#set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")

find_package(PkgConfig)

pkg_check_modules(LIBPCPP REQUIRED PcapPlusPlus)

add_library(pktvisorcore
        src/querypairmgr.cpp
        src/tcpsession.cpp
        src/metrics.cpp
        src/utils.cpp
        )

target_include_directories(pktvisorcore
        PUBLIC
        ${LIBPCPP_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/3rd/datasketches
        ${CMAKE_SOURCE_DIR}/3rd/datasketches/datasketches
        ${CMAKE_SOURCE_DIR}/3rd
        )

if (APPLE)
target_link_libraries(pktvisorcore
        PRIVATE
        "-L ${LIBPCPP_LIBRARY_DIRS}"
        ${LIBPCPP_LIBRARIES}
        "-framework CoreFoundation"
        "-framework SystemConfiguration"
        )
else()
    target_link_libraries(pktvisorcore
            PRIVATE
            ${LIBPCPP_LDFLAGS}
            ${LIBPCPP_LIBRARIES}
            )
endif()

add_executable(pktvisord
        3rd/docopt/docopt.cpp
        src/main.cpp
        )

target_link_libraries(pktvisord
        PRIVATE pktvisorcore
        )

add_executable(tests
        tests/main.cpp
        tests/test_parse_pcap.cpp
        tests/test_sketches.cpp
        tests/test_utils.cpp
        )

target_include_directories(tests SYSTEM
        PRIVATE ${CMAKE_SOURCE_DIR}/3rd/datasketches
        PRIVATE "${CMAKE_SOURCE_DIR}/3rd/catch"
        )

target_include_directories(tests
        PRIVATE "${CMAKE_SOURCE_DIR}/tests"
        PRIVATE "${CMAKE_SOURCE_DIR}/src"
        )

target_link_libraries(tests
        PRIVATE pktvisorcore
        )
