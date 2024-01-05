## TEST SUITE
add_executable(unit-tests-handler-flow
        main.cpp
        test_flows.cpp
        )

target_link_libraries(unit-tests-handler-flow
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Flow)

add_test(NAME unit-tests-handler-flow
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-flow
        )
