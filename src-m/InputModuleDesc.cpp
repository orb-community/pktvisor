#include "InputModuleDesc.h"

namespace pktvisor {

void InputModuleDesc::init_module(std::shared_ptr<pktvisor::InputManager> im, httplib::Server &svr)
{
    assert(im.get());
    _input_manager = im;
    _setup_routes(svr);
}

}
