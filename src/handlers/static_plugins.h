
int import_handler_plugins()
{
    CORRADE_PLUGIN_IMPORT(VisorHandlerNet);
    CORRADE_PLUGIN_IMPORT(VisorHandlerDns);
    CORRADE_PLUGIN_IMPORT(VisorHandlerPcap);
    return 0;
}

CORRADE_AUTOMATIC_INITIALIZER(import_handler_plugins)
