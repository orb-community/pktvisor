
# Unit
add_executable(unit-tests-handler-dns-v2
        main.cpp
        test_dns_layer.cpp
        test_dnstap.cpp
        )

target_link_libraries(unit-tests-handler-dns-v2
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Dns::V2)

add_test(NAME unit-tests-handler-dns-v2
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-dns-v2
        )