#include "AbstractMetricsManager.h"
#include <catch2/catch.hpp>

using namespace visor;

class TestMetricsBucket : public AbstractMetricsBucket
{
};

class TestMetricsManager : public AbstractMetricsManager<TestMetricsBucket>
{
};

TEST_CASE("Counter metrics", "[metrics][counter]")
{
    Metric::add_static_label("instance", "test instance");

    json j;
    Counter c("root", {"test", "metric"}, "A counter test metric");

    SECTION("Counter increment")
    {
        c.name_json_assign(j, 58);
        CHECK(j["test"]["metric"] == 58);
        ++c;
        c.to_json(j["top"]);
        CHECK(j["top"]["test"]["metric"] == 1);
        c += 4;
        c.to_json(j["top"]);
        CHECK(j["top"]["test"]["metric"] == 5);
    }

    SECTION("Counter add")
    {
        c.name_json_assign(j, {"add"}, 60);
        CHECK(j["test"]["metric"]["add"] == 60);
    }

    SECTION("Counter prometheus")
    {
        std::stringstream output;
        std::string line;
        ++c;
        c.to_prometheus(output, {{"policy", "default"}});
        std::getline(output, line);
        CHECK(line == "# HELP root_test_metric A counter test metric");
        std::getline(output, line);
        CHECK(line == "# TYPE root_test_metric gauge");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default"} 1)");
    }
}

TEST_CASE("Quantile metrics", "[metrics][quantile]")
{
    Metric::add_static_label("instance", "test instance");

    json j;
    Quantile<int_fast32_t> q("root", {"test", "metric"}, "A quantile test metric");

    SECTION("Quantile to json")
    {
        q.name_json_assign(j, 58);
        CHECK(j["test"]["metric"] == 58);
        int_fast32_t value = 12;
        q.update(value);
        q.to_json(j["top"]);
        CHECK(j["top"]["test"]["metric"]["p50"] == 12);
        CHECK(j["top"]["test"]["metric"]["p90"] == 12);
        CHECK(j["top"]["test"]["metric"]["p95"] == 12);
        CHECK(j["top"]["test"]["metric"]["p99"] == 12);
    }

    SECTION("Quantile get n")
    {
        q.update(12);
        auto other = q.get_n();
        CHECK(other == 1);
    }

    SECTION("Quantile get quantile")
    {
        q.update(12);
        auto result = q.get_quantile(0.5);
        CHECK(result == 12);
    }

    SECTION("Quantile prometheus")
    {
        std::stringstream output;
        std::string line;
        q.update(12);
        q.to_prometheus(output, {{"policy", "default"}});
        std::getline(output, line);
        CHECK(line == "# HELP root_test_metric A quantile test metric");
        std::getline(output, line);
        CHECK(line == "# TYPE root_test_metric summary");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default",quantile="0.5"} 12)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default",quantile="0.9"} 12)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default",quantile="0.95"} 12)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default",quantile="0.99"} 12)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric_sum{instance="test instance",policy="default"} 12)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric_count{instance="test instance",policy="default"} 1)");
    }
}

TEST_CASE("TopN metrics", "[metrics][topn]")
{
    Metric::add_static_label("instance", "test instance");

    json j;
    TopN<std::string> top_sting("root", {"test", "metric"}, "A topn test metric");
    TopN<uint16_t> top_int("root", {"test", "metric"}, "A topn test metric");

    SECTION("TopN to json")
    {
        top_sting.name_json_assign(j, 58);
        CHECK(j["test"]["metric"] == 58);
        top_sting.update("top1");
        top_sting.to_json(j["top"]);
        CHECK(j["top"]["test"]["metric"][0]["estimate"] == 1);
        CHECK(j["top"]["test"]["metric"][0]["name"] == "top1");
    }

    SECTION("TopN to json formatter")
    {
        top_int.name_json_assign(j, 58);
        CHECK(j["test"]["metric"] == 58);
        top_int.update(123);
        top_int.to_json(j["top"], [](const uint16_t &val) { return std::to_string(val); });
        CHECK(j["top"]["test"]["metric"][0]["estimate"] == 1);
        CHECK(j["top"]["test"]["metric"][0]["name"] == "123");
    }

    SECTION("TopN prometheus")
    {
        std::stringstream output;
        std::string line;
        top_sting.update("top1");
        top_sting.update("top2");
        top_sting.update("top1");
        top_sting.to_prometheus(output, {{"policy", "default"}});
        std::getline(output, line);
        CHECK(line == "# HELP root_test_metric A topn test metric");
        std::getline(output, line);
        CHECK(line == "# TYPE root_test_metric gauge");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",name="top1",policy="default"} 2)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",name="top2",policy="default"} 1)");
    }

    SECTION("TopN prometheus formatter")
    {
        std::stringstream output;
        std::string line;
        top_int.update(123);
        top_int.update(10);
        top_int.update(123);
        top_int.to_prometheus(output, {{"policy", "default"}},
            [](const uint16_t &val) { return std::to_string(val); });
        std::getline(output, line);
        CHECK(line == "# HELP root_test_metric A topn test metric");
        std::getline(output, line);
        CHECK(line == "# TYPE root_test_metric gauge");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",name="123",policy="default"} 2)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",name="10",policy="default"} 1)");
    }
}

TEST_CASE("Cardinality metrics", "[metrics][cardinality]")
{
    Metric::add_static_label("instance", "test instance");

    json j;
    Cardinality c("root", {"test", "metric"}, "A cardinality test metric");

    SECTION("Cardinality update")
    {
        c.name_json_assign(j, 58);
        CHECK(j["test"]["metric"] == 58);
        c.update("metric");
        c.to_json(j);
        CHECK(j["test"]["metric"] == 1);
        u_int8_t data[16] = {2, 0, 0, 1, ':', 'd', 'b', 8, ':', 3, 'c', 4, 'd', ':', 1, 5};
        c.update(reinterpret_cast<const void *>(data), 16);
        c.to_json(j["top"]);
        CHECK(j["top"]["test"]["metric"] == 2);
    }

    SECTION("Cardinality prometheus")
    {
        std::stringstream output;
        std::string line;
        c.update("metric");
        c.to_prometheus(output, {{"policy", "default"}});
        std::getline(output, line);
        CHECK(line == "# HELP root_test_metric A cardinality test metric");
        std::getline(output, line);
        CHECK(line == "# TYPE root_test_metric gauge");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default"} 1)");
    }
}

TEST_CASE("Rate metrics", "[metrics][rate]")
{
    Metric::add_static_label("instance", "test instance");

    json j;
    Rate r("root", {"test", "metric"}, "A rate test metric");

    SECTION("rate set info invalid name")
    {
        CHECK_THROWS_WITH(r.set_info("root", {"test*", "metric"}, "A rate test metric"), "invalid metric name: test*");
    }

    SECTION("rate set info invalid scheme")
    {
        CHECK_THROWS_WITH(r.set_info("root*", {"test", "metric"}, "A rate test metric"), "invalid schema name: root*");
    }

    SECTION("rate live json")
    {
        r.name_json_assign(j, 58);
        CHECK(j["test"]["metric"] == 58);
        r.to_json(j["top"], true);
        CHECK(j["top"]["test"]["metric"]["live"] == 0);
    }

    SECTION("rate prometheus")
    {
        std::stringstream output;
        r.to_prometheus(output, {{"policy", "default"}});
    }
}
