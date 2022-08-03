
# Unit
add_executable(unit-tests-visor-dns
        main.cpp
        test_dns.cpp
        )

target_link_libraries(unit-tests-visor-dns
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Dns)

add_test(NAME unit-tests-visor-dns
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-visor-dns
        )

# Benchmark
add_executable(benchmark-visor-dns
        benchmark_dns.cpp
        )

target_link_libraries(benchmark-visor-dns PRIVATE
        Visor::Dns
        ${CONAN_LIBS_BENCHMARK})
