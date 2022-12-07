
## TEST SUITE
add_executable(unit-tests-handler-bgp
        main.cpp
        test_bgp_layer.cpp
        test_json_schema.cpp
        )

target_link_libraries(unit-tests-handler-bgp
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Bgp)

add_test(NAME unit-tests-handler-bgp
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-bgp
        )
