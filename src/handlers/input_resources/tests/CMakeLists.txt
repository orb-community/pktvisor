
## TEST SUITE
add_executable(unit-tests-handler-input-resources-v1
        main.cpp
        test_resources_layer.cpp
        )

target_link_libraries(unit-tests-handler-input-resources-v1
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::InputResources::V1)

add_test(NAME unit-tests-handler-input-resources-v1
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-input-resources-v1
        )
