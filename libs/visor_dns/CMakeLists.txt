message(STATUS "Visor DNS Helper")

add_library(VisorDns
        dns.cpp
        DnsLayer.cpp
        DnsResource.cpp
        DnsResourceData.cpp
        querypairmgr.cpp
        )
add_library(Visor::Dns ALIAS VisorDns)

target_include_directories(VisorDns
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorDns
        PUBLIC
        ${CONAN_LIBS_ROBIN-HOOD-HASHING}
        ${CONAN_LIBS_PCAPPLUSPLUS}
        ${CONAN_LIBS_LIBPCAP}
        ${CONAN_LIBS_SPDLOG}
        ${CONAN_LIBS_FMT}
        )

add_subdirectory(tests)