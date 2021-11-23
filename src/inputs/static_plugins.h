
int import_input_plugins()
{
    CORRADE_PLUGIN_IMPORT(VisorInputMock);
    CORRADE_PLUGIN_IMPORT(VisorInputPcap);
    CORRADE_PLUGIN_IMPORT(VisorInputDnstap);
    return 0;
}

CORRADE_AUTOMATIC_INITIALIZER(import_input_plugins)
