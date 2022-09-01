## TEST SUITE
add_executable(unit-tests-handler-flow-v1
        main.cpp
        test_flows.cpp
        )

target_link_libraries(unit-tests-handler-flow-v1
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Flow::V1)

add_test(NAME unit-tests-handler-flow-v1
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-flow-v1
        )
