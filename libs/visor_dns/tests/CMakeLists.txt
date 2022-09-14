# Unit
add_executable(unit-tests-visor-dns
        main.cpp
        test_dns.cpp
        )

target_link_libraries(unit-tests-visor-dns
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Lib::Dns)

add_test(NAME unit-tests-visor-dns
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND unit-tests-visor-dns
        )

# Benchmark
add_executable(benchmark-visor-dns
        benchmark_dns.cpp
        )

target_link_libraries(benchmark-visor-dns PRIVATE
        Visor::Lib::Dns
        ${CONAN_LIBS_BENCHMARK})