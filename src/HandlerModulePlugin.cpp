#include "HandlerModulePlugin.h"
#include <Corrade/Utility/Format.h>
#include <Corrade/Utility/FormatStl.h>

namespace pktvisor {

void HandlerModulePlugin::init_module(InputStreamManager *im,
    HandlerManager *hm, HttpServer &svr)
{
    Corrade::Utility::print("Init input plugin: {}\n", name());
    assert(hm);
    assert(im);
    _input_manager = im;
    _handler_manager = hm;
    _setup_routes(svr);
}
void HandlerModulePlugin::init_module(InputStreamManager *im, HandlerManager *hm)
{
    Corrade::Utility::print("Init input plugin (without server): {}\n", name());
    assert(hm);
    assert(im);
    _input_manager = im;
    _handler_manager = hm;
}

}
