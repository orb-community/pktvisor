#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

class SpdlogInitializer : public Catch::EventListenerBase
{
public:
    using Catch::EventListenerBase::EventListenerBase;

    void testCaseStarting([[maybe_unused]] Catch::TestCaseInfo const &testInfo) override
    {
        static bool initialized = false;
        if (!initialized) {
            auto logger = spdlog::get("visor");
            if (!logger) {
                spdlog::stderr_color_mt("visor");
            }
            initialized = true;
        }
    }
};

CATCH_REGISTER_LISTENER(SpdlogInitializer)