
add_subdirectory(net)
add_subdirectory(dns)
add_subdirectory(pcap)

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} PARENT_SCOPE)
