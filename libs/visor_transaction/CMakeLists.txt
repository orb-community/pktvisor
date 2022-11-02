add_library(VisorLibTransaction INTERFACE)
add_library(Visor::Lib::Transaction ALIAS VisorLibTransaction)

target_include_directories(VisorLibTransaction
        INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_compile_features(VisorLibTransaction INTERFACE cxx_std_17)

target_sources(VisorLibTransaction
        INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/TransactionManager.h
        )