cmake_minimum_required(VERSION 3.9)
project(fstrm)

add_library(fstrm
        fstrm/control.c
        fstrm/file.c
        fstrm/iothr.c
        fstrm/rdwr.c
        fstrm/reader.c
        fstrm/tcp_writer.c
        fstrm/time.c
        fstrm/unix_writer.c
        fstrm/writer.c
        libmy/argv.c
        libmy/my_queue_mb.c
        libmy/my_queue_mutex.c
        )
add_library(fstrm::fstrm ALIAS fstrm)
target_compile_options(fstrm PRIVATE -Wno-pedantic -Wno-unused-variable -Wno-unused-but-set-variable)

target_include_directories(fstrm
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:$<INSTALL_PREFIX>>
        )

set(FSTRM_HEADERS
        fstrm/fstrm.h
        )
set_target_properties(fstrm PROPERTIES PUBLIC_HEADER "${FSTRM_HEADERS}")

