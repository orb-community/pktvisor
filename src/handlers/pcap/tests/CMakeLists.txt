
## TEST SUITE
add_executable(unit-tests-handler-pcap
        main.cpp
        test_pcap_layer.cpp
        test_json_schema.cpp
        )

target_link_libraries(unit-tests-handler-pcap
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::Pcap)

add_test(NAME unit-tests-handler-pcap
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-pcap
        )
