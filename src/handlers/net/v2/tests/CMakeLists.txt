
## TEST SUITE
if(WIN32)
    #dnstap not supported
    add_executable(unit-tests-handler-net-v2
            main.cpp
            test_json_schema.cpp
            )
else()
    add_executable(unit-tests-handler-net-v2
            main.cpp
            test_net_layer.cpp
            test_json_schema.cpp
            )
endif()

target_link_libraries(unit-tests-handler-net-v2
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Net::V2
        Visor::Handler::Dns::V2)

add_test(NAME unit-tests-handler-net-v2
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-net-v2
        )
