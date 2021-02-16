
int import_handler_plugins()
{
    CORRADE_PLUGIN_IMPORT(VizerHandlerNet);
    CORRADE_PLUGIN_IMPORT(VizerHandlerDns);
    return 0;
}

CORRADE_AUTOMATIC_INITIALIZER(import_handler_plugins)
