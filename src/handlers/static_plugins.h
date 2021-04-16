
int import_handler_plugins()
{
    CORRADE_PLUGIN_IMPORT(VisorHandlerNet);
    CORRADE_PLUGIN_IMPORT(VisorHandlerDns);
    return 0;
}

CORRADE_AUTOMATIC_INITIALIZER(import_handler_plugins)
