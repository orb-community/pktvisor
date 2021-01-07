#include "InputModulePlugin.h"

namespace pktvisor {

void InputModulePlugin::init_module(std::shared_ptr<pktvisor::InputStreamManager> im, httplib::Server &svr)
{
    assert(im.get());
    _input_manager = im;
    _setup_routes(svr);
}

}
