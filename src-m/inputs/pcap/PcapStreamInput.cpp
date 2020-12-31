#include "PcapStreamInput.h"
#include <Corrade/PluginManager/AbstractManager.h>

CORRADE_PLUGIN_REGISTER(PcapInput, pktvisor::input::pcap::PcapStreamInput,
    "com.ns1.module.input/1.0")
