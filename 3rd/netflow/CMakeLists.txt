add_library(netflow
        collector.c
        ipfix.c
        netflow_v1.c
        netflow_v5_v7.c
        netflow_v9.c
        )

target_include_directories(netflow
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_compile_features(netflow INTERFACE cxx_std_11)
