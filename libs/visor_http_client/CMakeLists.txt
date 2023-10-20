message(STATUS "Visor Lib HTTP Client")

add_library(VisorLibHttpClient
        httpssession.cpp
        tcpsession.cpp
        url_parser.c
        )
add_library(Visor::Lib::HttpClient ALIAS VisorLibHttpClient)

target_include_directories(VisorLibHttpClient
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        ${CONAN_LIBS_LIBNGHTTP2}
        )

target_link_libraries(VisorLibHttpClient
        PUBLIC
        ${CONAN_LIBS_LIBNGHTTP2}
        ${CONAN_LIBS_LIBUV}
        ${CONAN_LIBS_UVW}
        ${CONAN_LIBS_OPENSSL}
        )

## TEST SUITE
add_executable(unit-tests-visor-http-client test_driver.cpp)

target_link_libraries(unit-tests-visor-http-client
        PRIVATE
        Visor::Lib::HttpClient
        ${CONAN_LIBS_CATCH2})

add_test(NAME unit-tests-visor-http-client
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/libs/visor_http_client
        COMMAND unit-tests-visor-http-client)