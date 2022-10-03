#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>
#include <cstdlib>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

int main(int argc, char *argv[])
{
    Catch::Session session;

    auto logger = spdlog::get("visor");
    if (!logger) {
        spdlog::stderr_color_mt("visor");
        }

    int result = session.applyCommandLine(argc, argv);
    if (result != 0) {
        return result;
    }

    result = session.run();

    return (result == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
