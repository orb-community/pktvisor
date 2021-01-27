#include "InputModulePlugin.h"
#include <Corrade/Utility/Format.h>
#include <Corrade/Utility/FormatStl.h>

namespace pktvisor {

void InputModulePlugin::init_module(InputStreamManager *im, HttpServer &svr)
{
    Corrade::Utility::print("Init input plugin: {}\n", name());
    assert(im);
    _input_manager = im;
    _setup_routes(svr);
}
void InputModulePlugin::init_module(InputStreamManager *im)
{
    Corrade::Utility::print("Init input plugin (without server): {}\n", name());
    assert(im);
    _input_manager = im;
}

}
