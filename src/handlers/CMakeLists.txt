
add_subdirectory(net)
add_subdirectory(dns)
add_subdirectory(dns_xact)
add_subdirectory(flow)
add_subdirectory(dhcp)
add_subdirectory(pcap)
add_subdirectory(mock)
add_subdirectory(input_resources)

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} PARENT_SCOPE)
