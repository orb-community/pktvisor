add_library(sflow INTERFACE)

target_include_directories(sflow
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_compile_features(sflow INTERFACE cxx_std_11)

target_sources(sflow
        INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/sflow.h
        ${CMAKE_CURRENT_SOURCE_DIR}/sflow_v2v4.h
        )