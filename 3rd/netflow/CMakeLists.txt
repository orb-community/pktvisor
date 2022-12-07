add_library(netflow INTERFACE)

target_include_directories(netflow
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_compile_features(netflow INTERFACE cxx_std_11)

target_sources(netflow
        INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/netflow.h
        )
