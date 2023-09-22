message(STATUS "Visor Lib Utils")

add_library(VisorLibUtils
        utils.cpp
        )
add_library(Visor::Lib::Utils ALIAS VisorLibUtils)

target_include_directories(VisorLibUtils
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorLibUtils
        PUBLIC
        ${CONAN_LIBS_PCAPPLUSPLUS}
        ${CONAN_LIBS_PTHREADS4W}
        ${CONAN_LIBS_LIBPCAP}
        ${CONAN_LIBS_NPCAP}
        ${CONAN_LIBS_SPDLOG}
        ${CONAN_LIBS_FMT}
        )

## TEST SUITE
add_executable(unit-tests-visor-utils test_utils.cpp)

target_link_libraries(unit-tests-visor-utils
        PRIVATE
        ${CONAN_LIBS_JSON-SCHEMA-VALIDATOR}
        Visor::Lib::Utils
        ${CONAN_LIBS_CATCH2})

add_test(NAME unit-tests-visor-utils
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND unit-tests-visor-utils)