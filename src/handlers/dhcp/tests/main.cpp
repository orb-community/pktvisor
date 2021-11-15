#define CATCH_CONFIG_RUNNER
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
