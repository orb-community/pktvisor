add_executable(pktvisord
        main.cpp
        )

target_include_directories(pktvisord
        PRIVATE
        ${VIZER_VENDOR_DIR}
        ${VIZER_VENDOR_DIR}/datasketches
        ${VIZER_VENDOR_DIR}/datasketches/datasketches
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_BINARY_DIR}/src # FIXME config.h
        )

target_link_libraries(pktvisord PRIVATE vizer-core)
