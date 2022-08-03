
# Unit
add_executable(unit-tests-handler-dns
        main.cpp
        test_dns_layer.cpp
        test_dnstap.cpp
        test_json_schema.cpp
        )

target_link_libraries(unit-tests-handler-dns
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Dns)

add_test(NAME unit-tests-handler-dns
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-dns
        )
