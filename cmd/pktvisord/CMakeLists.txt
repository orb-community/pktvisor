add_executable(pktvisord main.cpp)

target_link_libraries(pktvisord
        PRIVATE
        ${CONAN_LIBS_CRASHPAD}
        timer
        resolv
        ${CONAN_LIBS_DOCOPT.CPP}
        Visor::Core
        ${VISOR_STATIC_PLUGINS}
        )

#copy conan crashpad built binary to binaries folder
if(NOT CRASHPAD_NOT_SUPPORTED)
configure_file("${CONAN_BIN_DIRS_CRASHPAD}/crashpad_handler" "${PROJECT_BINARY_DIR}/bin/crashpad_handler" COPYONLY)
endif()