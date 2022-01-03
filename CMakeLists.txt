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
            RESULT_VARIABLE
            SHORT_HASH_RESULT
            OUTPUT_VARIABLE
            SHORT_HASH)
    string(REGEX REPLACE "\n$" "" SHORT_HASH "${SHORT_HASH}")
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

# use a custom conan home directory in our build directory
# this allows us to use the clang-toolchain docker image in CLion docker toolchain
set(ENV{CONAN_USER_HOME} ${CMAKE_BINARY_DIR}/conan_home)
include(conan)

conan_add_remote(NAME ns1labs INDEX 1
        URL https://ns1labs.jfrog.io/artifactory/api/conan/ns1labs-conan
        VERIFY_SSL True)

conan_cmake_autodetect(settings)

execute_process(COMMAND ${CONAN_CMD} config set general.revisions_enabled=1)

# by default, build all conan dependencies that don't have a binary for this env
set(CONAN_BUILD_SETTING missing)

# Linux/clang/libc++/musl special requirements
if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif()
if(LINUX)
    # as of 1/1/2022 m4 inappropriately tries to use a GCC binary version, must force build
    set(CONAN_BUILD_SETTING ${CONAN_BUILD_SETTING} m4)
    foreach(SETTING ${settings})
        if (SETTING STREQUAL "compiler.libcxx=libc++")
            set(STATIC_BINARIES TRUE)
            # if std c++ lib is libc++ (llvm) + linux then assume no gcc is available
            # (stackoverflow says to check like this: ldd /bin/ls | grep 'musl' | head -1 | cut -d ' ' -f1)
            # in this case must manually link libexecinfo
            execute_process(COMMAND ${CONAN_CMD} profile update env.pcapplusplus:LDFLAGS=-lexecinfo default)
        endif()
    endforeach()
endif()

if(STATIC_BINARIES)
set(STATIC_FLAGS -static -lc++ -lc++abi)
endif()

conan_cmake_install(PATH_OR_REFERENCE ${CMAKE_SOURCE_DIR}
        BUILD ${CONAN_BUILD_SETTING}
        GENERATOR cmake
        SETTINGS ${settings}
        INSTALL_FOLDER ${CMAKE_BINARY_DIR})

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

find_package(Corrade REQUIRED PluginManager)
include(sanitizer)

set(VISOR_STATIC_PLUGINS)

enable_testing()

message(STATUS "Building pktvisor version ${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}.${CMAKE_PROJECT_VERSION_MINOR}${VISOR_PRERELEASE}")
add_subdirectory(3rd)
add_subdirectory(src)
add_subdirectory(cmd)
add_subdirectory(integration_tests)

# golang version
configure_file(golang/pkg/client/version.go.in ${CMAKE_SOURCE_DIR}/golang/pkg/client/version.go)
