
## TEST SUITE
add_executable(unit-tests-handler-resources
        main.cpp
        test_resources_layer.cpp
        )

target_link_libraries(unit-tests-handler-resources
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Resources)

add_test(NAME unit-tests-handler-resources
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
        COMMAND unit-tests-handler-resources
        )
