#ifndef PKTVISORD_STREAMINPUT_H
#define PKTVISORD_STREAMINPUT_H

#include <tuple>

namespace pktvisor {

class StreamInput
{

public:

    virtual void start() = 0;
    virtual void stop() = 0;
    virtual ~StreamInput(){};
};

}

#endif //PKTVISORD_STREAMINPUT_H
