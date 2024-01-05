
## TEST SUITE
add_executable(unit-tests-handler-input-resources
        main.cpp
        test_resources_layer.cpp
        )

target_link_libraries(unit-tests-handler-input-resources
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::InputResources)

add_test(NAME unit-tests-handler-input-resources
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-input-resources
        )
