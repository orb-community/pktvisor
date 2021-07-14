
add_library(rng INTERFACE)

target_include_directories(rng
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_compile_features(rng INTERFACE cxx_std_11)

target_sources(rng
        INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/jsf.h
        )