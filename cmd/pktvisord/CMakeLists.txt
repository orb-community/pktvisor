add_executable(pktvisord main.cpp)

target_include_directories(pktvisord
        PRIVATE
        ${CMAKE_BINARY_DIR}/src # Vizer::Core config.h
        )

target_link_libraries(pktvisord
        PRIVATE
        timer
        resolv
        ${CONAN_LIBS_DOCOPT.CPP}
        Vizer::Core
        ${VIZER_STATIC_PLUGINS}
        )
