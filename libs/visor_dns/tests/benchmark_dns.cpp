/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include "dns.h"
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wzero-as-null-pointer-constant"
#pragma clang diagnostic ignored "-Wc99-extensions"
#endif
#include "IPv4Layer.h"
#include "PacketUtils.h"
#include "PcapFileDevice.h"
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

using namespace visor::lib::dns;

void BM_aggregateDomain(const std::string &domain)
{
    AggDomainResult result;
    result = aggregateDomain(domain);
}

void BM_pcapReadNoParse()
{
    auto reader = pcpp::IFileReaderDevice::getReader("tests/dns_udp_tcp_random.pcap");

    if (!reader->open()) {
        throw std::runtime_error("Cannot open pcap/pcapng file");
    }

    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket)) {
    }

    reader->close();
    delete reader;
}

void BM_pcapReadParse()
{

    auto reader = pcpp::IFileReaderDevice::getReader("tests/dns_udp_tcp_random.pcap");

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

TEST_CASE("DNS benchmark")
{
    BENCHMARK("Aggregate Domain")
    {
        return BM_aggregateDomain("biz.foo.bar.com");
    };

    BENCHMARK("Aggregate Domain Long")
    {
        return BM_aggregateDomain("long1.long2.long3.long4.long5.long6.long7.long8.biz.foo.bar.com");
    };

    BENCHMARK("Pcap Read No Parse")
    {
        return BM_pcapReadNoParse();
    };

    BENCHMARK("Pcap Read No Parse")
    {
        return BM_pcapReadParse();
    };
}
