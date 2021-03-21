/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "../dns.h"
#include <benchmark/benchmark.h>

using namespace visor::handler::dns;

static void BM_aggregateDomain(benchmark::State &state)
{
    AggDomainResult result;
    std::string domain{"biz.foo.bar.com"};
    for (auto _ : state) {
        result = aggregateDomain(domain);
    }
}
BENCHMARK(BM_aggregateDomain);

static void BM_aggregateDomainLong(benchmark::State &state)
{
    AggDomainResult result;
    std::string domain{"long1.long2.long3.long4.long5.long6.long7.long8.biz.foo.bar.com"};
    for (auto _ : state) {
        result = aggregateDomain(domain);
    }
}

BENCHMARK(BM_aggregateDomainLong);

BENCHMARK_MAIN();