# Unit
add_executable(unit-tests-visor-utils
        main.cpp
        test_utils.cpp
        )

target_link_libraries(unit-tests-visor-utils
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Lib::Utils)

add_test(NAME unit-tests-visor-utils
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND unit-tests-visor-utils
        )