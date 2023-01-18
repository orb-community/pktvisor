
## TEST SUITE
if(WIN32)
    #dnstap not supported
    add_executable(unit-tests-handler-net
            main.cpp
            test_json_schema.cpp
            )
else()
    add_executable(unit-tests-handler-net
            main.cpp
            test_net_layer.cpp
            test_json_schema.cpp
            )
endif()

target_link_libraries(unit-tests-handler-net
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Net
        Visor::Handler::Dns)

add_test(NAME unit-tests-handler-net
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-net
        )
