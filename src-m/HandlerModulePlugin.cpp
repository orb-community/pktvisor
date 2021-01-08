#include "HandlerModulePlugin.h"
#include <Corrade/Utility/Format.h>
#include <Corrade/Utility/FormatStl.h>

namespace pktvisor {

void HandlerModulePlugin::init_module(std::shared_ptr<pktvisor::HandlerManager> im, HttpServer &svr)
{
    Corrade::Utility::print("Init input plugin: {}\n", name());
    assert(im.get());
    _handler_manager = im;
    _setup_routes(svr);
}

}
