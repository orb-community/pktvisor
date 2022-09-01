
# Unit
add_executable(unit-tests-handler-dns-v1
        main.cpp
        test_dns_layer.cpp
        test_dnstap.cpp
        test_json_schema.cpp
        )

target_link_libraries(unit-tests-handler-dns-v1
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Dns::V1)

add_test(NAME unit-tests-handler-dns-v1
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-dns-v1
        )