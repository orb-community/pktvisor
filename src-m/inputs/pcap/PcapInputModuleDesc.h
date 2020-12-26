
#ifndef PKTVISORD_PCAPINPUTMODULEDESC_H
#define PKTVISORD_PCAPINPUTMODULEDESC_H

#include "InputModuleDesc.h"
#include "singleton/Singleton.hpp"

namespace pktvisor {
class PcapInputModuleDesc : public InputModuleDesc
{
public:
    PcapInputModuleDesc();
};
}

extern lib::Singleton<pktvisor::PcapInputModuleDesc> PcapInputModule;

#endif //PKTVISORD_PCAPINPUTMODULEDESC_H
