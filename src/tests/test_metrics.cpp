#include "AbstractMetricsManager.h"
#include <catch2/catch.hpp>

using namespace pktvisor;

class TestMetricsBucket : public AbstractMetricsBucket
{
};

class TestMetricsManager : public AbstractMetricsManager<TestMetricsBucket>
{
};

TEST_CASE("metrics", "[metrics]")
{
    //    TestMetricsManager metrics{1, 100};
}
