cmake_minimum_required(VERSION 3.13)

message(STATUS "Modular support will build")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/3rd/corrade/modules")

find_package(Corrade REQUIRED PluginManager)

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

add_library(pktvisorcore-m
        AbstractPlugin.cpp
        InputStreamManager.cpp
        HandlerManager.cpp
        StreamHandler.cpp
        InputStream.cpp
        InputModulePlugin.cpp
        HandlerModulePlugin.cpp
        )

target_include_directories(pktvisorcore-m
        PRIVATE
        ${PKTVISOR_VENDOR_DIR}
        ${CORRADE_INCLUDE_DIR}
        ${Corrade_BINARY_DIR}/src # FIXME configure.h, probably not right
        )

target_link_libraries(pktvisorcore-m
        PRIVATE
        Corrade::PluginManager
        )

configure_file(config.h.in config.h @ONLY)

add_subdirectory(inputs/pcap)

add_subdirectory(handlers/net)
#add_subdirectory(handlers/dns)

set(PKTVISOR_STATIC_PLUGINS ${PKTVISOR_STATIC_PLUGINS} PARENT_SCOPE)
