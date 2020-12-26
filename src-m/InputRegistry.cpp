#include "InputRegistry.h"
#include <iostream>

// TODO move to generated include file
#include "inputs/pcap/PcapInputModuleDesc.h"
// TODO

pktvisor::InputRegistryClass::InputRegistryClass()
{
    std::cout << "construct input registry\n";
}
void pktvisor::InputRegistryClass::get_registry() const
{
    std::cout << "getting input registry\n";
}
void pktvisor::InputRegistryClass::register_module(const std::string &mod)
{
    std::cout << "registering input module: " << mod << "\n";
    _modules.emplace_back(mod);
}
void pktvisor::InputRegistryClass::init_registry()
{
    std::cout << "initing input registry (no-op)\n";
    // TODO move to generated include file
    // no-op, forces initialization
    PcapInputModule.get_const_instance();
    // TODO --
}

lib::Singleton<pktvisor::InputRegistryClass> InputRegistry;
