message(STATUS "Visor Lib TCP Helper")

add_library(VisorLibTcp
        VisorTcpLayer.cpp
        )
add_library(Visor::Lib::Tcp ALIAS VisorLibTcp)

target_include_directories(VisorLibTcp
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        )

target_link_libraries(VisorLibTcp
        PUBLIC
        ${CONAN_LIBS_PCAPPLUSPLUS}
        ${CONAN_LIBS_PTHREADS4W}
        ${CONAN_LIBS_LIBPCAP}
        ${CONAN_LIBS_NPCAP}
        )
