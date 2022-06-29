#include "AbstractMetricsManager.h"
#include <catch2/catch.hpp>

using namespace visor;

class TestMetricsBucket : public AbstractMetricsBucket
{
public:
    void specialized_merge([[maybe_unused]] const AbstractMetricsBucket &other)
    {
    }
    void to_json([[maybe_unused]] json &j) const
    {
    }
    void to_prometheus([[maybe_unused]] std::stringstream &out,
        [[maybe_unused]] Metric::LabelMap add_labels = {}) const
    {
        out << "test_performed" << std::endl;
    }
    void update_topn_metrics([[maybe_unused]] size_t topn_count)
    {
    }
};

class TestMetricsManager : public AbstractMetricsManager<TestMetricsBucket>
{
public:
    TestMetricsManager(const Configurable *windowConfig)
        : AbstractMetricsManager(windowConfig){};
    ~TestMetricsManager() = default;
};

TEST_CASE("Abstract metrics manager", "[metrics][abstract]")
{
    json j;
    std::stringstream output;
    std::string line;
    visor::Config c;
    c.config_set<uint64_t>("num_periods", 1);
    c.config_set<uint64_t>("deep_sample_rate", 102);
    std::unique_ptr<TestMetricsManager> manager = std::make_unique<TestMetricsManager>(&c);

    SECTION("Check Configs")
    {
        CHECK(manager->num_periods() == 1);
        CHECK(manager->deep_sample_rate() == 100);
    }

    SECTION("Abstract window single json")
    {
        manager->window_single_json(j, "metrics");
        CHECK(j["metrics"]["period"]["length"] == 0);
    }

    SECTION("Abstract window single json failed")
    {
        CHECK_THROWS_WITH(manager->window_single_json(j, "metrics", 2), "invalid metrics period, specify [0, 0]");
    }

    SECTION("Abstract window single prometheus")
    {
        manager->window_single_prometheus(output, 0, {{"policy", "default"}});
        std::getline(output, line);
        CHECK(line == "test_performed");
    }

    SECTION("Abstract window single prometheus failed")
    {
        CHECK_THROWS_WITH(manager->window_single_prometheus(output, 2, {{"policy", "default"}}),
            "invalid metrics period, specify [0, 0]");
    }

    SECTION("Abstract window merged json failed")
    {
        CHECK_THROWS_WITH(manager->window_merged_json(j, "metrics", 0), "invalid metrics period, specify [2, 1]");
    }
}

TEST_CASE("Counter metrics", "[metrics][counter]")
{
    Metric::add_static_label("instance", "test instance");

    json j;
    std::stringstream output;
    std::string line;
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
    std::stringstream output;
    std::string line;
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
    std::stringstream output;
    std::string line;
    TopN<std::string> top_sting("root", "string", {"test", "metric"}, "A topn test metric");
    TopN<uint16_t> top_int("root", "integer", {"test", "metric"}, "A topn test metric");

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
        top_sting.update("top1");
        top_sting.update("top2");
        top_sting.update("top1");
        top_sting.to_prometheus(output, {{"policy", "default"}});
        std::getline(output, line);
        CHECK(line == "# HELP root_test_metric A topn test metric");
        std::getline(output, line);
        CHECK(line == "# TYPE root_test_metric gauge");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default",string="top1"} 2)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",policy="default",string="top2"} 1)");
    }

    SECTION("TopN prometheus formatter")
    {
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
        CHECK(line == R"(root_test_metric{instance="test instance",integer="123",policy="default"} 2)");
        std::getline(output, line);
        CHECK(line == R"(root_test_metric{instance="test instance",integer="10",policy="default"} 1)");
    }

    SECTION("TopN get count size")
    {
        CHECK(top_sting.topn_count() == 10);
        CHECK(top_int.topn_count() == 10);
    }

    SECTION("TopN update count size")
    {
        top_sting.update("top1");
        top_sting.update("top2");
        top_sting.update("top1");
        CHECK(top_sting.topn_count() == 10);
        top_sting.set_topn_count(1);
        CHECK(top_sting.topn_count() == 1);
        top_sting.to_json(j["top"]);
        CHECK(j["top"]["test"]["metric"][0]["estimate"] == 2);
        CHECK(j["top"]["test"]["metric"][0]["name"] == "top1");
        CHECK(j["top"]["test"]["metric"][1] == nullptr);
    }
}

TEST_CASE("Cardinality metrics", "[metrics][cardinality]")
{
    Metric::add_static_label("instance", "test instance");

    json j;
    std::stringstream output;
    std::string line;
    Cardinality c("root", {"test", "metric"}, "A cardinality test metric");

    SECTION("Cardinality update")
    {
        c.name_json_assign(j, 58);
        CHECK(j["test"]["metric"] == 58);
        c.update("metric");
        c.to_json(j);
        CHECK(j["test"]["metric"] == 1);
        uint8_t data[16] = {2, 0, 0, 1, ':', 'd', 'b', 8, ':', 3, 'c', 4, 'd', ':', 1, 5};
        c.update(reinterpret_cast<const void *>(data), 16);
        c.to_json(j["top"]);
        CHECK(j["top"]["test"]["metric"] == 2);
    }

    SECTION("Cardinality prometheus")
    {
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
    std::stringstream output;
    std::string line;
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
        r.to_prometheus(output, {{"policy", "default"}});
    }
}
