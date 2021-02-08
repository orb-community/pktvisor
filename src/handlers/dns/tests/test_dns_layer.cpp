#include "DnsLayer.h"
#include <Packet.h>
#include <PcapFileDevice.h>
#include <ProtocolType.h>
#include <UdpLayer.h>
#include <arpa/inet.h>
#include <catch2/catch.hpp>
#include <datasketches/fi/frequent_items_sketch.hpp>

#include "DnsStreamHandler.h"
#include "PcapInputStream.h"

using namespace pktvisor::handler::dns;
using namespace pktvisor::input::pcap;

TEST_CASE("Parse DNS UDP IPv4 tests, basic DnsLayer functionality", "[pcap][ipv4][udp][dns]")
{

    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "fixtures/dns_ipv4_udp.pcap");
    stream.config_set("bpf", "");

    DnsStreamHandler dns_handler{"dns-test", &stream, 1, 100};

    stream.start();
    stream.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();

    CHECK(counters.UDP == 140);
    CHECK(counters.queries == 210);
    CHECK(counters.replies == 210);
}

TEST_CASE("Parse DNS TCP IPv4 tests", "[pcap][ipv4][tcp][dns]")
{
    PcapInputStream stream{"pcap-test"};
    stream.config_set("pcap_file", "fixtures/dns_ipv4_tcp.pcap");
    stream.config_set("bpf", "");

    DnsStreamHandler dns_handler{"dns-test", &stream, 1, 100};

    stream.start();
    stream.stop();

    auto counters = dns_handler.metrics()->bucket(0)->counters();

    CHECK(counters.TCP == 2100);
    CHECK(counters.queries == 210);
    CHECK(counters.replies == 210);
}

TEST_CASE("Parse DNS UDP IPv6 tests", "[pcap][ipv6][udp][dns]")
{

    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader("fixtures/dns_ipv6_udp.pcap");

    CHECK(reader->open());

    pcpp::RawPacket rawPacket;
    int numUDP(0);
    int numDNS(0);
    while (reader->getNextPacket(rawPacket)) {
        // only parse to transport layer (in this case udp) so we can do our own dns
        pcpp::Packet request(&rawPacket, pcpp::OsiModelTransportLayer);
        // udp layer life cycle is managed by packet
        pcpp::UdpLayer *udpLayer = request.getLayerOfType<pcpp::UdpLayer>();
        CHECK(udpLayer != nullptr);
        numUDP++;
        // custom DNS layer, life cycle maintained manually
        DnsLayer dnsLayer = DnsLayer(udpLayer, &request);
        // manually resource parse
        dnsLayer.parseResources(true);
        // only check the first packet by name
        if (numDNS == 0) {
            CHECK(dnsLayer.getFirstQuery() != nullptr);
            CHECK(dnsLayer.getFirstQuery()->getName() == "LOJ5Pq2._EmpLuAPR.PPLIop.1F8J2R1.eMVq5.test.com");
            CHECK(dnsLayer.getFirstQuery()->getDnsType() == DNS_TYPE_AAAA);
        }
        numDNS++;
    }

    reader->close();
    delete reader;

    SECTION("Parse counts")
    {
        CHECK(numUDP == 140);
        CHECK(numDNS == 140);
    }
}
/*
TEST_CASE("Parse DNS TCP IPv6 tests", "[pcap][ipv6][tcp][dns]")
{


    bool firstQuery(false);
    int numTCP(0);
    int numDNS[2] = {0,0};

    auto got_dns_message = [&firstQuery, &numDNS](DnsLayer *dnsLayer, Direction dir, pcpp::ProtocolType l3, uint32_t flowKey, timespec stamp) {
        CHECK(stamp.tv_sec != 0);
        CHECK(stamp.tv_nsec != 0);
        if (firstQuery) {
            CHECK(dnsLayer->getFirstQuery()->getName() == "BCEIOL4.PfzdEtQk.lf.test.com");
            CHECK(dnsLayer->getFirstQuery()->getDnsType() == DNS_TYPE_AAAA);
            firstQuery = false;
        }
        numDNS[dir]++;
    };
    TcpDnsReassembly tcpDnsReassembly(got_dns_message);

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


*/