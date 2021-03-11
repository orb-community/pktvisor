/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

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
