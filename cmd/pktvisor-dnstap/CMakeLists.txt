add_executable(pktvisor-dnstap main.cpp)

target_include_directories(pktvisor-dnstap
        PRIVATE
        ${CMAKE_BINARY_DIR}/src # Visor::Core config.h
        )

target_link_libraries(pktvisor-dnstap
        PRIVATE
        ${CONAN_LIBS_DOCOPT.CPP}
        ${VISOR_STATIC_PLUGINS}
        )
