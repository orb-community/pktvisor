/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "HandlerModulePlugin.h"

namespace visor {

void HandlerModulePlugin::init_module(InputStreamManager *im,
    HandlerManager *hm, HttpServer *svr)
{
    assert(hm);
    assert(im);
    _input_manager = im;
    _handler_manager = hm;
    if (svr) {
        _setup_routes(svr);
    }
}

}
