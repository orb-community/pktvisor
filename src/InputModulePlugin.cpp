#include "InputModulePlugin.h"
#include <Corrade/Utility/Format.h>
#include <Corrade/Utility/FormatStl.h>

namespace vizer {

void InputModulePlugin::init_module(InputStreamManager *im, HttpServer &svr)
{
    assert(im);
    _input_manager = im;
    _setup_routes(svr);
}
void InputModulePlugin::init_module(InputStreamManager *im)
{
    assert(im);
    _input_manager = im;
}

}
