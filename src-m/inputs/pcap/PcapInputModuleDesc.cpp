
#include <iostream>

#include "InputRegistry.h"
#include "PcapInputModuleDesc.h"

extern lib::Singleton<pktvisor::InputRegistryClass> InputRegistry;

static pktvisor::PcapInputModuleDesc *PcapInputModule;
pktvisor::PcapInputModuleDesc *GetPcapInputModule(void)
{
    PcapInputModule = new pktvisor::PcapInputModuleDesc();
    return PcapInputModule;
}

pktvisor::PcapInputModuleDesc::PcapInputModuleDesc()
    : InputModuleDesc("pcap")
{
    std::cout << "construct pcap input module\n";
    InputRegistry.get_mutable_instance().register_module(PcapInputModule);
}
