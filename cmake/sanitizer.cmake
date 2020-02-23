# vim: set ts=4 sw=4 expandtab:

option(ASAN "Build with ASAN." OFF)
SET(SANITIZE "" CACHE STRING "Compile with sanitizer.")

if (ASAN)
    SET(SANITIZE "address")
endif()

if (SANITIZE)
    message(STATUS "Enabled sanitizer level ${SANITIZE}")
    add_compile_options(-fsanitize=${SANITIZE})
    link_libraries(-fsanitize=${SANITIZE})
endif()

