#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wc99-extensions"
#pragma clang diagnostic ignored "-Wrange-loop-analysis"
#include <Packet.h>
#include <PcapFileDevice.h>
#include <ProtocolType.h>
#include <UdpLayer.h>
#include <catch2/catch.hpp>
#include <frequent_items_sketch.hpp>
#pragma GCC diagnostic pop
#pragma GCC diagnostic ignored "-Wold-style-cast"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif


TEST_CASE("Top K Src Ports", "[pcap][ipv4][topk][dns][udp]")
{

    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("tests/fixtures/dns_ipv4_udp.pcap");

    CHECK(reader->open());

    pcpp::RawPacket rawPacket;

    datasketches::frequent_items_sketch<uint16_t> sketch(3);

    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet dnsRequest(&rawPacket);
        if (dnsRequest.isPacketOfType(pcpp::UDP)) {
            pcpp::UdpLayer *udpLayer = dnsRequest.getLayerOfType<pcpp::UdpLayer>();
            sketch.update(htons(udpLayer->getUdpHeader()->portSrc));
        }
    }

    reader->close();
    delete reader;

    auto items = sketch.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
    CHECK(items.size() == 5);
    CHECK(53000 == items[0].get_item());
    CHECK(70 == (int) items[0].get_estimate());

}

