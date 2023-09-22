message(STATUS "Visor Lib DNS Helper")

add_library(VisorLibDns
        dns.cpp
        DnsLayer.cpp
        DnsResource.cpp
        DnsResourceData.cpp
        )
add_library(Visor::Lib::Dns ALIAS VisorLibDns)

target_include_directories(VisorLibDns
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorLibDns
        PUBLIC
        Visor::Lib::Tcp
        ${CONAN_LIBS_PCAPPLUSPLUS}
        ${CONAN_LIBS_PTHREADS4W}
        ${CONAN_LIBS_LIBPCAP}
        ${CONAN_LIBS_NPCAP}
        ${CONAN_LIBS_SPDLOG}
        ${CONAN_LIBS_FMT}
        )

## TEST SUITE
add_executable(unit-tests-visor-dns tests/test_dns.cpp)

target_link_libraries(unit-tests-visor-dns 
        PRIVATE
        Visor::Lib::Dns
        ${CONAN_LIBS_CATCH2})

add_test(NAME unit-tests-visor-dns
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND unit-tests-visor-dns)

# Benchmark
add_executable(benchmark-visor-dns tests/benchmark_dns.cpp)

target_link_libraries(benchmark-visor-dns
        PRIVATE
        Visor::Lib::Dns
        ${CONAN_LIBS_BENCHMARK}
        ${CONAN_LIBS_CATCH2})