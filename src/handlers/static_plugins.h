#pragma once

int import_handler_plugins()
{
    CORRADE_PLUGIN_IMPORT(VisorHandlerNetV1);
    CORRADE_PLUGIN_IMPORT(VisorHandlerDnsV1);
    CORRADE_PLUGIN_IMPORT(VisorHandlerDnsV2);
    CORRADE_PLUGIN_IMPORT(VisorHandlerBgpV1);
    CORRADE_PLUGIN_IMPORT(VisorHandlerFlowV1);
    CORRADE_PLUGIN_IMPORT(VisorHandlerDhcpV1);
    CORRADE_PLUGIN_IMPORT(VisorHandlerPcapV1);
    CORRADE_PLUGIN_IMPORT(VisorHandlerInputResourcesV1);
    return 0;
}

CORRADE_AUTOMATIC_INITIALIZER(import_handler_plugins)
