
#include <iostream>

#include "HandlerRegistry.h"
#include "NetHandlerModuleDesc.h"

extern lib::Singleton<pktvisor::HandlerRegistryClass> HandlerRegistry;

pktvisor::NetHandlerModuleDesc::NetHandlerModuleDesc()
{
    std::cout << "construct net handler module\n";
    HandlerRegistry.get_mutable_instance().register_module("net");
}

lib::Singleton<pktvisor::NetHandlerModuleDesc> NetHandlerModule;
