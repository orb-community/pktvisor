cmake_minimum_required(VERSION 3.13)

message(STATUS "Modular support will build")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/3rd/corrade/modules")

find_package(Corrade REQUIRED PluginManager)

set_directory_properties(PROPERTIES CORRADE_USE_PEDANTIC_FLAGS ON)

add_library(pktvisorcore-m
        InputManager.cpp
        HandlerManager.cpp
        StreamHandler.cpp
        StreamInput.cpp
        InputModuleDesc.cpp
        HandlerModuleDesc.cpp
        )

target_include_directories(pktvisorcore-m
        PRIVATE
        ${PKTVISOR_VENDOR_DIR}
        ${CORRADE_INCLUDE_DIR}
        ${Corrade_BINARY_DIR}/src # FIXME configure.h, probably not right
        )

if (APPLE)
    target_link_libraries(pktvisorcore-m
            PRIVATE
            "-framework CoreFoundation"
            "-framework SystemConfiguration"
            Corrade::PluginManager
            )
else ()
    target_link_libraries(pktvisorcore-m
            PRIVATE
            Corrade::PluginManager
            )
endif ()

configure_file(config.h.in config.h @ONLY)


add_subdirectory(inputs/pcap)

#add_subdirectory(handlers/net)
#add_subdirectory(handlers/dns)
