#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wrange-loop-analysis"
#include <catch2/catch.hpp>
#include <cpc_sketch.hpp>
#include <frequent_items_sketch.hpp>
#include <kll_sketch.hpp>
#pragma GCC diagnostic pop
#pragma GCC diagnostic ignored "-Wold-style-cast"

TEST_CASE("Top-K", "[topk]")
{

    SECTION("Top K Basic")
    {
        datasketches::frequent_items_sketch<std::string> sketch(3);
        sketch.update("a");
        CHECK(!sketch.is_empty());
    }

    SECTION("Top K Freq Items")
    {
        datasketches::frequent_items_sketch<int> sketch(3);
        sketch.update(1, 10);
        sketch.update(2);
        sketch.update(3);
        sketch.update(4);
        sketch.update(5);
        sketch.update(6);
        sketch.update(7, 15);
        sketch.update(8);
        sketch.update(9);
        sketch.update(10);
        sketch.update(11);
        sketch.update(12);
        CHECK(sketch.get_maximum_error() > 0); // estimation mode

        CHECK(!sketch.is_empty());
        CHECK(35 == (int) sketch.get_total_weight());

        auto items = sketch.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_POSITIVES);
        CHECK(2 == (int) items.size()); // only 2 items (1 and 7) should have counts more than 1
        CHECK(7 == items[0].get_item());
        CHECK(15 == (int) items[0].get_estimate());
        CHECK(1 == items[1].get_item());
        CHECK(10 == (int) items[1].get_estimate());

        items = sketch.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        CHECK(2 <= (int) items.size()); // at least 2 items
        CHECK(12 >= (int) items.size()); // but not more than 12 items

    }


}

TEST_CASE("Distinct Count", "[cpc]")
{

    SECTION("CPC Basic")
    {
        datasketches::cpc_sketch sketch(11);
        const int n(10000);
        for (int i = 0; i < n; i++) sketch.update(i);
        CHECK(!sketch.is_empty());
        CHECK(sketch.get_estimate() >= sketch.get_lower_bound(1));
        CHECK(sketch.get_estimate() <= sketch.get_upper_bound(1));
        CHECK(sketch.validate());
    }

}
TEST_CASE("Quantiles", "[kll]")
{

    SECTION("KLL Basic")
    {
        datasketches::kll_sketch<float> sketch;
        const uint32_t n(200);
        for (uint32_t i = 0; i < n; i++) {
            sketch.update(i);
            CHECK((uint64_t) i + 1 == sketch.get_n());
        }
        CHECK(!sketch.is_empty());
        CHECK(!sketch.is_estimation_mode());
        CHECK(n == sketch.get_num_retained());
        CHECK(0.0f == sketch.get_min_value());
        CHECK(0.0f == sketch.get_quantile(0));
        CHECK((float) n - 1 == sketch.get_max_value());
        CHECK((float) n - 1 == sketch.get_quantile(1));

        const double fractions[3] {0, 0.5, 1};
        auto quantiles = sketch.get_quantiles(fractions, 3);
        CHECK(3 == (int) quantiles.size());
        CHECK(0.0f == quantiles[0]);
        CHECK((float) n / 2 == quantiles[1]);
        CHECK((float) n - 1 == quantiles[2]);

        for (uint32_t i = 0; i < n; i++) {
            const double trueRank = (double) i / n;
            CHECK(trueRank == sketch.get_rank(i));
        }
    }

}

