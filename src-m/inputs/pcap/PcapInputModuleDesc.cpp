
#include <iostream>

#include "InputRegistry.h"
#include "PcapInputModuleDesc.h"

extern lib::Singleton<pktvisor::InputRegistryClass> InputRegistry;

pktvisor::PcapInputModuleDesc::PcapInputModuleDesc()
{
    std::cout << "construct pcap input module\n";
    InputRegistry.get_mutable_instance().register_module("pcap");
}

lib::Singleton<pktvisor::PcapInputModuleDesc> PcapInputModule;
