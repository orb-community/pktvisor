
add_subdirectory(net)
add_subdirectory(dns)
add_subdirectory(dhcp)
add_subdirectory(pcap)
add_subdirectory(mock)

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} PARENT_SCOPE)
