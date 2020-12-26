#ifndef PKTVISORD_HANDLERREGISTRY_H
#define PKTVISORD_HANDLERREGISTRY_H

#include "singleton/Singleton.hpp"
#include <string>
#include <vector>

namespace pktvisor {

class HandlerRegistryClass
{
    std::vector<std::string> _modules;

public:
    HandlerRegistryClass();
    void init_registry();
    void get_registry() const;
    void register_module(const std::string &mod);
};

}

extern lib::Singleton<pktvisor::HandlerRegistryClass> HandlerRegistry;

#endif //PKTVISORD_HANDLERREGISTRY_H
