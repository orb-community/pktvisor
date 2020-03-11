#include <DnsLayer.h>
#include <UdpLayer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <ProtocolType.h>
#include <catch2/catch.hpp>
#include <datasketches/fi/frequent_items_sketch.hpp>
#include <arpa/inet.h>

#include "tcpsession.h"

TEST_CASE("Parse DNS UDP IPv4 tests", "[pcap][ipv4][udp][dns]")
{

    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("fixtures/dns_ipv4_udp.pcap");

    CHECK(reader->open());

    pcpp::RawPacket rawPacket;
    int numUDP(0);
    int numDNS(0);
    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet dnsRequest(&rawPacket);
        if (dnsRequest.isPacketOfType(pcpp::UDP)) {
            numUDP++;
            if (dnsRequest.isPacketOfType(pcpp::DNS)) {
                pcpp::DnsLayer *dnsLayer = dnsRequest.getLayerOfType<pcpp::DnsLayer>();
                if (numDNS == 0) {
                    CHECK(dnsLayer->getFirstQuery()->getName() == "utadwnME.POJwOc9R.KtfO.test.com");
                    CHECK(dnsLayer->getFirstQuery()->getDnsType() == pcpp::DNS_TYPE_AAAA);
                }
                numDNS++;
            }
        }
    }

    reader->close();
    delete reader;

    SECTION("Parse counts")
    {
        CHECK(numUDP == 140);
        CHECK(numDNS == 140);
    }
}

TEST_CASE("Parse DNS TCP IPv4 tests", "[pcap][ipv4][tcp][dns]")
{


    int numTCP(0);
    bool firstQuery(false);
    int numDNS[2] = {0,0};

    auto got_dns_message = [&firstQuery, &numDNS](pcpp::DnsLayer* dnsLayer, pktvisor::Direction dir, pcpp::ProtocolType l3, uint32_t flowKey, timeval stamp) {
        CHECK(stamp.tv_sec != 0);
        CHECK(stamp.tv_usec != 0);
        if (firstQuery) {
            CHECK(dnsLayer->getFirstQuery()->getName() == "hx.3FsQRh6.ollah70Na.test.com");
            CHECK(dnsLayer->getFirstQuery()->getDnsType() == pcpp::DNS_TYPE_AAAA);
            firstQuery = false;
        }
        numDNS[dir]++;
    };
    pktvisor::TcpDnsReassembly tcpDnsReassembly(got_dns_message);

    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("fixtures/dns_ipv4_tcp.pcap");

    CHECK(reader->open());

    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet dnsRequest(&rawPacket);
        if (dnsRequest.isPacketOfType(pcpp::TCP)) {
            numTCP++;
            tcpDnsReassembly.getTcpReassembly()->reassemblePacket(&rawPacket);
        }
    }

    reader->close();
    delete reader;

    SECTION("Parse counts")
    {
        // total packets
        CHECK(numTCP == 2100);
        // client side dns msgs (queries)
        CHECK(numDNS[0] == 210);
        // server side dns msgs (replies)
        CHECK(numDNS[1] == 210);
    }
}

TEST_CASE("Parse DNS UDP IPv6 tests", "[pcap][ipv6][udp][dns]")
{

    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("fixtures/dns_ipv6_udp.pcap");

    CHECK(reader->open());

    pcpp::RawPacket rawPacket;
    int numUDP(0);
    int numDNS(0);
    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet dnsRequest(&rawPacket);
        if (dnsRequest.isPacketOfType(pcpp::UDP)) {
            numUDP++;
            if (dnsRequest.isPacketOfType(pcpp::DNS)) {
                pcpp::DnsLayer *dnsLayer = dnsRequest.getLayerOfType<pcpp::DnsLayer>();
                if (numDNS == 0) {
                    CHECK(dnsLayer->getFirstQuery()->getName() == "LOJ5Pq2._EmpLuAPR.PPLIop.1F8J2R1.eMVq5.test.com");
                    CHECK(dnsLayer->getFirstQuery()->getDnsType() == pcpp::DNS_TYPE_AAAA);
                }
                numDNS++;
            }
        }
    }

    reader->close();
    delete reader;

    SECTION("Parse counts")
    {
        CHECK(numUDP == 140);
        CHECK(numDNS == 140);
    }
}

TEST_CASE("Parse DNS TCP IPv6 tests", "[pcap][ipv6][tcp][dns]")
{


    bool firstQuery(false);
    int numTCP(0);
    int numDNS[2] = {0,0};

    auto got_dns_message = [&firstQuery, &numDNS](pcpp::DnsLayer* dnsLayer, pktvisor::Direction dir, pcpp::ProtocolType l3, uint32_t flowKey, timeval stamp) {
        CHECK(stamp.tv_sec != 0);
        CHECK(stamp.tv_usec != 0);
        if (firstQuery) {
            CHECK(dnsLayer->getFirstQuery()->getName() == "BCEIOL4.PfzdEtQk.lf.test.com");
            CHECK(dnsLayer->getFirstQuery()->getDnsType() == pcpp::DNS_TYPE_AAAA);
            firstQuery = false;
        }
        numDNS[dir]++;
    };
    pktvisor::TcpDnsReassembly tcpDnsReassembly(got_dns_message);

    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("fixtures/dns_ipv6_tcp.pcap");

    CHECK(reader->open());

    pcpp::RawPacket rawPacket;
    while (reader->getNextPacket(rawPacket)) {
        pcpp::Packet dnsRequest(&rawPacket);
        if (dnsRequest.isPacketOfType(pcpp::TCP)) {
            numTCP++;
            tcpDnsReassembly.getTcpReassembly()->reassemblePacket(&rawPacket);
        }
    }

    // close the reader and free its memory
    reader->close();
    delete reader;

    SECTION("Parse counts")
    {
        // total packets
        CHECK(numTCP == 1800);
        // client side dns msgs (queries)
        CHECK(numDNS[0] == 180);
        // server side dns msgs (replies)
        CHECK(numDNS[1] == 180);
    }

}

TEST_CASE("Top K Src Ports", "[pcap][ipv4][topk][dns][udp]")
{

    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("fixtures/dns_ipv4_udp.pcap");

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

