message(STATUS "Input Module: Dnstap")

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

find_package(Protobuf REQUIRED)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS pb/dnstap.proto)

if(WIN32)
corrade_add_static_plugin(VisorInputDnstap ${CMAKE_CURRENT_BINARY_DIR}
        Dnstap.conf
        DnstapInputModulePlugin.cpp
        FakeDnstapInputStream.cpp
        ${PROTO_SRCS}
        )
add_library(Visor::Input::Dnstap ALIAS VisorInputDnstap)

target_include_directories(VisorInputDnstap
        PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}> # for generated dnstap.pb.h
        )

target_link_libraries(VisorInputDnstap
        PUBLIC
        Visor::Core
        ${CONAN_LIBS_PROTOBUF}
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Input::Dnstap PARENT_SCOPE)

else()
corrade_add_static_plugin(VisorInputDnstap ${CMAKE_CURRENT_BINARY_DIR}
        Dnstap.conf
        DnstapInputModulePlugin.cpp
        DnstapInputStream.cpp
        ${PROTO_SRCS}
        )
add_library(Visor::Input::Dnstap ALIAS VisorInputDnstap)

target_include_directories(VisorInputDnstap
        PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}> # for generated dnstap.pb.h
        )

target_link_libraries(VisorInputDnstap
        PUBLIC
        fstrm
        Visor::Core
        ${CONAN_LIBS_PROTOBUF}
        ${CONAN_LIBS_LIBUV}
        ${CONAN_LIBS_UVW}
        )

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} Visor::Input::Dnstap PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-input-dnstap
        tests/main.cpp
        tests/test_dnstap.cpp
        )

target_link_libraries(unit-tests-input-dnstap
        PRIVATE Visor::Input::Dnstap
        )

add_test(NAME unit-tests-input-dnstap
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND unit-tests-input-dnstap
        )
endif()