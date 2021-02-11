message(STATUS "Handler Module: DNS")

#pkg_check_modules(LIBPCPP REQUIRED PcapPlusPlus)

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

corrade_add_static_plugin(vizer-handler-dns
        ${CMAKE_CURRENT_BINARY_DIR}
        DnsHandler.conf
        DnsHandlerModulePlugin.cpp
        DnsStreamHandler.cpp
        dns.cpp
        querypairmgr.cpp
        # DnsLayer
        DnsLayer.cpp
        DnsResource.cpp
        DnsResourceData.cpp
        )
add_library(Vizer::Handler::Dns ALIAS vizer-handler-dns)

#target_include_directories(vizer-handler-dns
#        PRIVATE
#        ${LIBPCPP_INCLUDE_DIRS}
#        ${CMAKE_SOURCE_DIR}/src # FIXME ?
#        ${CMAKE_SOURCE_DIR}/src/inputs/pcap # FIXME - dependency on pcap
#        )

#if (APPLE)
#    target_link_libraries(DnsHandler
#            PRIVATE
#            "-L${LIBPCPP_LIBRARY_DIRS}"
#            ${LIBPCPP_LIBRARIES}
#            "-framework CoreFoundation"
#            "-framework SystemConfiguration"
#            )
#else ()
#    target_link_libraries(DnsHandler
#            PRIVATE
#            ${LIBPCPP_LDFLAGS}
#            ${LIBPCPP_LIBRARIES}
#            )
#endif ()

target_link_libraries(vizer-handler-dns
        PRIVATE
        Vizer::Input::Pcap
        )

set(VIZER_STATIC_PLUGINS ${VIZER_STATIC_PLUGINS} vizer-handler-dns PARENT_SCOPE)

## TEST SUITE
add_executable(unit-tests-handler-dns
        tests/main.cpp
        tests/test_dns.cpp
        tests/test_dns_layer.cpp
        )

#target_include_directories(unit-tests-handler-dns
#        PRIVATE
#
#        )

target_link_libraries(unit-tests-handler-dns PRIVATE Vizer::Handler::Dns)

