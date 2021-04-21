/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "InputModulePlugin.h"

namespace visor {

void InputModulePlugin::init_module(InputStreamManager *im, HttpServer *svr)
{
    assert(im);
    _input_manager = im;
    if (svr) {
        _setup_routes(svr);
    }
}

}
