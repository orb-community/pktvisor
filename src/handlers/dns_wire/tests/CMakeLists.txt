
# Unit
add_executable(unit-tests-handler-dns-wire
        main.cpp
        test_dns_wire_layer.cpp
        test_dns_wire_dnstap.cpp
        test_json_schema.cpp
        )

target_link_libraries(unit-tests-handler-dns-wire
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Dns::Wire)

add_test(NAME unit-tests-handler-dns-wire
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-dns-wire
        )