add_executable(pktvisor-sflow main.cpp)

target_include_directories(pktvisor-sflow
        PRIVATE
        ${CMAKE_BINARY_DIR}/src # Visor::Core config.h
        )

target_link_libraries(pktvisor-sflow
        PRIVATE
        ${CONAN_LIBS_DOCOPT.CPP}
        ${VISOR_STATIC_PLUGINS}
        ${STATIC_FLAGS}
        )
