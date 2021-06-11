add_executable(pktvisor-pcap main.cpp)

target_include_directories(pktvisor-pcap
        PRIVATE
        ${CMAKE_BINARY_DIR}/src # Visor::Core config.h
        )

target_link_libraries(pktvisor-pcap
        PRIVATE
        ${CONAN_LIBS_DOCOPT.CPP}
        Visor::Handler::Net
        Visor::Handler::Dns
        Visor::Handler::Pcap
        Visor::Input::Mock
        )
