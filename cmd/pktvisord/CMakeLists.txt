add_executable(pktvisord main.cpp)

target_include_directories(pktvisord
        PRIVATE
        ${CMAKE_BINARY_DIR}/src # Visor::Core config.h
        )

if (MUSL)
    set(PKTVISORD_STATIC -static -lc++ -lc++abi)
endif()

target_link_libraries(pktvisord
        PRIVATE
        timer
        resolv
        ${CONAN_LIBS_DOCOPT.CPP}
        Visor::Core
        ${VISOR_STATIC_PLUGINS}
        ${PKTVISORD_STATIC}
        )
