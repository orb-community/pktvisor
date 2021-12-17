
add_subdirectory(mock)
add_subdirectory(pcap)
add_subdirectory(dnstap)

set(VISOR_STATIC_PLUGINS ${VISOR_STATIC_PLUGINS} PARENT_SCOPE)
