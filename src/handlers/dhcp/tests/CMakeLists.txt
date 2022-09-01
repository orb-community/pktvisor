
## TEST SUITE
add_executable(unit-tests-handler-dhcp-v1
        main.cpp
        test_dhcp_layer.cpp
        test_json_schema.cpp
        )

target_link_libraries(unit-tests-handler-dhcp-v1
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Dhcp::V1)

add_test(NAME unit-tests-handler-dhcp-v1
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-dhcp-v1
        )
