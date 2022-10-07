
## TEST SUITE
add_executable(unit-tests-handler-netprobe
        main.cpp
        test_net_probe.cpp
        )

target_link_libraries(unit-tests-handler-netprobe
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Handler::NetProbe)

add_test(NAME unit-tests-handler-netprobe
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-handler-netprobe
        )
