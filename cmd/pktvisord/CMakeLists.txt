add_executable(pktvisord
        ${PKTVISOR_VENDOR_DIR}/docopt/docopt.cpp
        main.cpp
        )

target_include_directories(pktvisord
        PRIVATE
        ${PKTVISOR_VENDOR_DIR}
        ${CORRADE_INCLUDE_DIR}
        ${PKTVISOR_VENDOR_DIR}/datasketches
        ${PKTVISOR_VENDOR_DIR}/datasketches/datasketches
        ${CMAKE_SOURCE_DIR}/src
        ${Corrade_BINARY_DIR}/src # FIXME configure.h, probably not right
        ${CMAKE_BINARY_DIR}/src # FIXME config.h
        )

target_link_libraries(pktvisord PRIVATE pktvisorcore ${PKTVISOR_STATIC_PLUGINS})
