add_executable(pktvisor-pcap main.cpp)

target_include_directories(pktvisor-pcap
        PRIVATE
        ${CMAKE_BINARY_DIR}/src # Vizer::Core config.h
        )

target_link_libraries(pktvisor-pcap
        PRIVATE
        ${CONAN_LIBS_DOCOPT.CPP}
        Vizer::Handler::Net
        Vizer::Handler::Dns)
