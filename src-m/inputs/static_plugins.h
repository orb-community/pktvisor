
int import_input_plugins()
{
    CORRADE_PLUGIN_IMPORT(PcapInput);
    return 0;
}

CORRADE_AUTOMATIC_INITIALIZER(import_input_plugins)
