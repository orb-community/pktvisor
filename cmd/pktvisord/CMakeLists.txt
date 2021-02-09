add_executable(pktvisord
        ${VIZER_VENDOR_DIR}/docopt/docopt.cpp
        main.cpp
        )

target_include_directories(pktvisord
        PRIVATE
        ${VIZER_VENDOR_DIR}
        ${CORRADE_INCLUDE_DIR}
        ${VIZER_VENDOR_DIR}/datasketches
        ${VIZER_VENDOR_DIR}/datasketches/datasketches
        ${CMAKE_SOURCE_DIR}/src
        ${Corrade_BINARY_DIR}/src # FIXME configure.h, probably not right
        ${CMAKE_BINARY_DIR}/src # FIXME config.h
        )

target_link_libraries(pktvisord PRIVATE vizer-core ${VIZER_STATIC_PLUGINS})
