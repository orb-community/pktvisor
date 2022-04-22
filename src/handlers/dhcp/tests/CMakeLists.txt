
## TEST SUITE
add_executable(unit-tests-handler-dhcp
        main.cpp
        test_dhcp_layer.cpp
        test_json_schema.cpp
        )

target_link_libraries(unit-tests-handler-dhcp
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Dhcp)

add_test(NAME unit-tests-handler-dhcp
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
        COMMAND unit-tests-handler-dhcp
        )
