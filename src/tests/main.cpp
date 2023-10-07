#define CATCH_CONFIG_RUNNER
#include <Corrade/PluginManager/AbstractManager.h>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-declarations"
#endif
#include "inputs/static_plugins.h"
#include "handlers/static_plugins.h"
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <catch2/catch.hpp>
#include <cstdlib>

int main(int argc, char *argv[])
{
    Catch::Session session;

    int result = session.applyCommandLine(argc, argv);
    if (result != 0) {
        return result;
    }

    result = session.run();

    return (result == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
