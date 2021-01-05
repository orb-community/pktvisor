#ifndef PKTVISORD_PCAPSTREAMINPUT_H
#define PKTVISORD_PCAPSTREAMINPUT_H

#include "StreamInput.h"

namespace pktvisor {
namespace input {

class PcapStreamInput : public pktvisor::StreamInput
{
public:
    PcapStreamInput()
        : pktvisor::StreamInput()
    {
    }
};

}
}

#endif //PKTVISORD_PCAPSTREAMINPUT_H
