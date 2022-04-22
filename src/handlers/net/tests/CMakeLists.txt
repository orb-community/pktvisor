
## TEST SUITE
add_executable(unit-tests-handler-net
        main.cpp
        test_net_layer.cpp
        test_json_schema.cpp
        )

target_link_libraries(unit-tests-handler-net
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Net)

add_test(NAME unit-tests-handler-net
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
        COMMAND unit-tests-handler-net
        )
