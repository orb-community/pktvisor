#include "HandlerModulePlugin.h"
#include <Corrade/Utility/Format.h>
#include <Corrade/Utility/FormatStl.h>

namespace pktvisor {

void HandlerModulePlugin::init_module(std::shared_ptr<pktvisor::InputStreamManager> im,
    std::shared_ptr<pktvisor::HandlerManager> hm, HttpServer &svr)
{
    Corrade::Utility::print("Init input plugin: {}\n", name());
    assert(hm.get());
    assert(im.get());
    _input_manager = im;
    _handler_manager = hm;
    _setup_routes(svr);
}

}
