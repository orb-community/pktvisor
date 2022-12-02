message(STATUS "Visor Lib Utils")

add_library(VisorLibUtils
        utils.cpp
        )
add_library(Visor::Lib::Utils ALIAS VisorLibUtils)

target_include_directories(VisorLibUtils
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorLibUtils
        PUBLIC
        ${CONAN_LIBS_PCAPPLUSPLUS}
        ${CONAN_LIBS_PTHREADS4W}
        ${CONAN_LIBS_LIBPCAP}
        ${CONAN_LIBS_NPCAP}
        ${CONAN_LIBS_SPDLOG}
        ${CONAN_LIBS_FMT}
        )

add_subdirectory(tests)