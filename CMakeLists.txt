cmake_minimum_required(VERSION 3.13)

#######################################################
# VERSION
#######################################################

# this is the source of truth for semver version
project(visor VERSION 3.4.0)

# for main line release, this is empty
# for development release, this is "-develop"
# for release candidate, this is "-rc"
set(VISOR_PRERELEASE "-develop")

#######################################################

# if develop or rc build, add git hash
# note this only updates on cmake reconfigure, not every git commit
# so it's mainly useful for GitHub CI, not developers
if(VISOR_PRERELEASE STREQUAL "-develop" OR VISOR_PRERELEASE STREQUAL "-rc")
    execute_process(
            COMMAND
            git rev-parse --short HEAD
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            RESULT_VARIABLE
            SHORT_HASH_RESULT
            OUTPUT_VARIABLE
            SHORT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (${SHORT_HASH} STREQUAL "")
        message(FATAL "Unable to get current git hash for develop/rc version")
    endif ()
    string(APPEND VISOR_PRERELEASE "-${SHORT_HASH}")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# these are computed
set(VISOR_VERSION_NUM "${PROJECT_VERSION}${VISOR_PRERELEASE}")
set(VISOR_VERSION "pktvisor ${PROJECT_VERSION}${VISOR_PRERELEASE}")

# used in CI
file(WRITE ${CMAKE_BINARY_DIR}/VERSION ${VISOR_VERSION_NUM})
######

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 ")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
#set(CMAKE_VERBOSE_MAKEFILE ON)
add_compile_options(-Wall -pedantic -W -Wextra -Wno-unknown-pragmas)

# Conan setup

set(PKTVISOR_CONAN_INIT ON CACHE BOOL "Create new Conan environment for the build.")
set(PKTVISOR_CONAN_BUILD_PROFILE "default" CACHE STRING "Profile for the build environment.")
set(PKTVISOR_CONAN_HOST_PROFILE "default" CACHE STRING "Profile for the host environment.")

include(conan)

# setup new environment by default but allow using an existing one
# this also allows us to use the clang-toolchain docker image in CLion docker toolchain
if(PKTVISOR_CONAN_INIT)
    message(STATUS "Creating new Conan environment.")
    set(ENV{CONAN_USER_HOME} ${CMAKE_BINARY_DIR}/conan_home)
    execute_process(COMMAND ${CONAN_CMD} config set "general.revisions_enabled=1")
    execute_process(COMMAND ${CONAN_CMD} profile update settings.compiler.libcxx=libstdc++11 default)
    conan_add_remote(NAME ns1labs INDEX 0
            URL https://ns1labs.jfrog.io/artifactory/api/conan/ns1labs-conan
            VERIFY_SSL True)
endif()

conan_cmake_autodetect(CONAN_SETTINGS)
message(STATUS "Detected conan settings: ${CONAN_SETTINGS}")

# by default, build all conan dependencies that don't have a binary for this env
set(CONAN_BUILD_SETTING missing)
set(CONAN_ENV_SETTING "")

conan_cmake_install(PATH_OR_REFERENCE ${CMAKE_SOURCE_DIR}
        BUILD ${CONAN_BUILD_SETTING}
        PROFILE_BUILD ${PKTVISOR_CONAN_BUILD_PROFILE}
        PROFILE_HOST ${PKTVISOR_CONAN_HOST_PROFILE}
        GENERATOR cmake
        SETTINGS ${CONAN_SETTINGS}
        ENV ${CONAN_ENV_SETTING}
        INSTALL_FOLDER ${CMAKE_BINARY_DIR})

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

find_package(Corrade REQUIRED PluginManager)
include(sanitizer)

set(VISOR_STATIC_PLUGINS)

enable_testing()

message(STATUS "Building pktvisor version ${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}.${CMAKE_PROJECT_VERSION_PATCH}${VISOR_PRERELEASE}")
add_subdirectory(3rd)
add_subdirectory(src)
add_subdirectory(cmd)
add_subdirectory(integration_tests)

# golang version
configure_file(golang/pkg/client/version.go.in ${CMAKE_SOURCE_DIR}/golang/pkg/client/version.go)
