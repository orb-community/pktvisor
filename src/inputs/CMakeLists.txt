
add_subdirectory(mock)
add_subdirectory(pcap)
add_subdirectory(dnstap)
add_subdirectory(flow)
add_subdirectory(netprobe)

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} PARENT_SCOPE)
