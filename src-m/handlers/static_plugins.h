
int import_handler_plugins()
{
    CORRADE_PLUGIN_IMPORT(NetHandler);
    return 0;
}

CORRADE_AUTOMATIC_INITIALIZER(import_handler_plugins)
