add_executable(pktvisor-pcap main.cpp)

target_link_libraries(pktvisor-pcap
        PRIVATE
        ${CONAN_LIBS_DOCOPT.CPP}
        ${VISOR_STATIC_PLUGINS}
        )
