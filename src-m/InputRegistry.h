#ifndef PKTVISORD_INPUTREGISTRY_H
#define PKTVISORD_INPUTREGISTRY_H

#include "singleton/Singleton.hpp"
#include <string>
#include <vector>

namespace pktvisor {

class InputRegistryClass
{
    std::vector<std::string> _modules;

public:
    InputRegistryClass();
    void init_registry();
    void get_registry() const;
    void register_module(const std::string &mod);
};

}

extern lib::Singleton<pktvisor::InputRegistryClass> InputRegistry;

#endif //PKTVISORD_INPUTREGISTRY_H
