
#ifndef PKTVISORD_NETHANDLERMODULEDESC_H
#define PKTVISORD_NETHANDLERMODULEDESC_H

#include "HandlerModulePlugin.h"
#include "singleton/Singleton.hpp"

namespace pktvisor {
class NetHandlerModuleDesc : public HandlerModuleDesc
{
public:
    NetHandlerModuleDesc();
};
}

extern lib::Singleton<pktvisor::NetHandlerModuleDesc> NetHandlerModule;

#endif //PKTVISORD_NETHANDLERMODULEDESC_H
