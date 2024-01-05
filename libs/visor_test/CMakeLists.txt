message(STATUS "Visor Lib Test Helper")

add_library(VisorLibTest INTERFACE)
add_library(Visor::Lib::Test ALIAS VisorLibTest)

target_include_directories(VisorLibTest
    INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

target_link_libraries(VisorLibTest
    INTERFACE
    ${CONAN_LIBS_SPDLOG}
    ${CONAN_LIBS_CATCH2})

target_compile_features(VisorLibTest INTERFACE cxx_std_17)

target_sources(VisorLibTest INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/catch2/catch_test_visor.hpp)