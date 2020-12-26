#include "HandlerRegistry.h"
#include <iostream>

// TODO move to generated include file
#include "handlers/net/NetHandlerModuleDesc.h"
// TODO

pktvisor::HandlerRegistryClass::HandlerRegistryClass()
{
    std::cout << "construct handler registry\n";
}
void pktvisor::HandlerRegistryClass::get_registry() const
{
    std::cout << "getting handler registry\n";
}
void pktvisor::HandlerRegistryClass::register_module(const std::string &mod)
{
    std::cout << "registering handler module: " << mod << "\n";
    _modules.emplace_back(mod);
}
void pktvisor::HandlerRegistryClass::init_registry()
{
    std::cout << "initing handler registry (no-op)\n";
    // TODO move to all generated include file
    // no-op, forces initialization
    NetHandlerModule.get_const_instance();
    // TODO --
}

lib::Singleton<pktvisor::HandlerRegistryClass> HandlerRegistry;
