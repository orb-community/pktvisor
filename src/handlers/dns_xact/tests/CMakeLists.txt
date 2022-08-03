
# Unit
add_executable(unit-tests-handler-dns-xact
        main.cpp
        test_dns_xact_layer.cpp
        #test_dnstap.cpp
        test_json_schema.cpp
        )

target_link_libraries(unit-tests-handler-dns-xact
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::DnsXact)

add_test(NAME unit-tests-handler-dns-xact
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-dns-xact
        )
