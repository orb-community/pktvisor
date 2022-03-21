add_executable(pktvisor-reader main.cpp)

target_link_libraries(pktvisor-reader
        PRIVATE
        ${CONAN_LIBS_DOCOPT.CPP}
        ${VISOR_STATIC_PLUGINS}
        )
