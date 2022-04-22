add_executable(pktvisor-reader main.cpp)

target_include_directories(pktvisor-reader
        PRIVATE
        ${CMAKE_BINARY_DIR}/src # Visor::Core config.h
        )

target_link_libraries(pktvisor-reader
        PRIVATE
        ${CONAN_LIBS_DOCOPT.CPP}
        ${VISOR_STATIC_PLUGINS}
        ${STATIC_FLAGS}
        )
