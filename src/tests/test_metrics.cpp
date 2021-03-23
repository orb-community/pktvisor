#include "AbstractMetricsManager.h"
#include <catch2/catch.hpp>

using namespace visor;

class TestMetricsBucket : public AbstractMetricsBucket
{
};

class TestMetricsManager : public AbstractMetricsManager<TestMetricsBucket>
{
};

TEST_CASE("metrics", "[metrics]")
{
    Counter c("root", {"test", "metric"}, "A test metric");

    json j;
    c.name_json_assign(j, 58);
    CHECK(j["test"]["metric"] == 58);
    ++c;
    c.to_json(j["top"]);
    CHECK(j["top"]["test"]["metric"] == 1);

    json j2;
    Counter c2("root", {"test", "metric"}, "A test metric");
    c2.name_json_assign(j2, {"add"}, 60);
    CHECK(j2["test"]["metric"]["add"] == 60);
}
