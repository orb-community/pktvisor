message(STATUS "Handler Module: Net")

pkg_check_modules(LIBPCPP REQUIRED PcapPlusPlus)

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(vizer-handler-net
        ${CMAKE_CURRENT_BINARY_DIR}
        NetHandler.conf
        NetHandlerModulePlugin.cpp
        NetStreamHandler.cpp)
add_library(Vizer::Handler::Net ALIAS vizer-handler-net)

#target_include_directories(NetHandler
#        PRIVATE
#        ${VIZER_VENDOR_DIR}
#        # FIXME
#        ${VIZER_VENDOR_DIR}/datasketches
#        ${VIZER_VENDOR_DIR}/datasketches/datasketches
#        #
#        ${LIBPCPP_INCLUDE_DIRS}
#        ${CMAKE_SOURCE_DIR}/src # FIXME ?
#        ${CMAKE_SOURCE_DIR}/src/inputs/pcap # FIXME - dependency on pcap
#        )

#if (APPLE)
#    target_link_libraries(NetHandler
#            PRIVATE
#            "-L${LIBPCPP_LIBRARY_DIRS}"
#            ${LIBPCPP_LIBRARIES}
#            "-framework CoreFoundation"
#            "-framework SystemConfiguration"
#            )
#else ()
#    target_link_libraries(NetHandler
#            PRIVATE
#            ${LIBPCPP_LDFLAGS}
#            ${LIBPCPP_LIBRARIES}
#            )
#endif ()

target_link_libraries(vizer-handler-net
        PRIVATE
        Vizer::Input::Pcap
        )

set(VIZER_STATIC_PLUGINS ${VIZER_STATIC_PLUGINS} vizer-handler-net PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-handler-net
        tests/main.cpp
        tests/test_net_layer.cpp
        )

#target_include_directories(unit-tests-handler-net
#        PRIVATE
#        ${VIZER_VENDOR_DIR}
#        ${VIZER_VENDOR_DIR}/catch
#        ${CMAKE_CURRENT_SOURCE_DIR}
#        #
#        ${LIBPCPP_INCLUDE_DIRS}  # pcpp
#        ${CMAKE_SOURCE_DIR}/src # core
#        ${CMAKE_SOURCE_DIR}/src/inputs/pcap # PcapInputStream
#        ${VIZER_VENDOR_DIR}/datasketches
#        ${VIZER_VENDOR_DIR}/datasketches/datasketches
#        )

target_link_libraries(unit-tests-handler-net PRIVATE Vizer::Handler::Net)
