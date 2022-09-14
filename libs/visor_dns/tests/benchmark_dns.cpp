/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "benchmark/benchmark.h"
#include "dns.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wc99-extensions"
#pragma GCC diagnostic ignored "-Wpedantic"
#include "IPv4Layer.h"
#include "PacketUtils.h"
#include "PcapFileDevice.h"
#pragma GCC diagnostic pop

using namespace visor::lib::dns;

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

static void BM_pcapReadNoParse(benchmark::State &state)
{

    for (auto _ : state) {
        auto reader = pcpp::IFileReaderDevice::getReader("fixtures/dns_udp_tcp_random.pcap");

        if (!reader->open()) {
            throw std::runtime_error("Cannot open pcap/pcapng file");
        }

        pcpp::RawPacket rawPacket;
        while (reader->getNextPacket(rawPacket)) {
        }

        reader->close();
        delete reader;
    }
}
BENCHMARK(BM_pcapReadNoParse);

static void BM_pcapReadParse1(benchmark::State &state)
{

    for (auto _ : state) {
        auto reader = pcpp::IFileReaderDevice::getReader("fixtures/dns_udp_tcp_random.pcap");

        if (!reader->open()) {
            throw std::runtime_error("Cannot open pcap/pcapng file");
        }

        pcpp::RawPacket rawPacket;
        while (reader->getNextPacket(rawPacket)) {
            pcpp::Packet packet(&rawPacket, pcpp::OsiModelTransportLayer);
        }

        reader->close();
        delete reader;
    }
}
BENCHMARK(BM_pcapReadParse1);

BENCHMARK_MAIN();