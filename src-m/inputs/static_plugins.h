
int import_plugins()
{
    CORRADE_PLUGIN_IMPORT(PcapInput);
    return 0;
}

CORRADE_AUTOMATIC_INITIALIZER(import_plugins)
