
## TEST SUITE
add_executable(unit-tests-handler-pcap-v1
        main.cpp
        test_pcap_layer.cpp
        test_json_schema.cpp
        )

target_link_libraries(unit-tests-handler-pcap-v1
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Pcap::V1)

add_test(NAME unit-tests-handler-pcap-v1
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-pcap-v1
        )
