#include <cstdint>
#include <cstring>
#include <map>
#include <utility>
#include <iostream>

#include <DnsLayer.h>

#include "pktvisor.h"
#include "tcpsession.h"

namespace pktvisor {

TcpDnsSession::TcpDnsSession(
    malformed_data_cb malformed_data_handler,
    got_dns_msg_cb got_dns_msg_handler)
    : _malformed_data{std::move(malformed_data_handler)}
    , _got_dns_msg{std::move(got_dns_msg_handler)}
{
}

// accumulate data and try to extract DNS messages
void TcpDnsSession::receive_data(const char data[], size_t len)
{
    const size_t MIN_DNS_QUERY_SIZE = 17;
    const size_t MAX_DNS_QUERY_SIZE = 512;

    _buffer.append(data, len);

    for (;;) {
        std::uint16_t size;

        if (_buffer.size() < sizeof(size))
            break;

        // size is in network byte order.
        size = static_cast<unsigned char>(_buffer[1]) | static_cast<unsigned char>(_buffer[0]) << 8;

        if (size < MIN_DNS_QUERY_SIZE || size > MAX_DNS_QUERY_SIZE) {
            _malformed_data();
            break;
        }

        if (_buffer.size() >= sizeof(size) + size) {
            auto data = std::make_unique<char[]>(size);
            std::memcpy(data.get(), _buffer.data() + sizeof(size), size);
            _buffer.erase(0, sizeof(size) + size);
            _got_dns_msg(std::move(data), size);
        } else {
            // Nope, we need more data.
            break;
        }
    }
}

static void tcpReassemblyConnectionStartCallback(const pcpp::ConnectionData& connectionData, void *userCookie)
{

    // only track DNS connections
    if (!pcpp::DnsLayer::isDnsPort(connectionData.srcPort) && !pcpp::DnsLayer::isDnsPort(connectionData.dstPort)) {
        return;
    }

    TcpReassemblyMgr *reassemblyMgr = (TcpReassemblyMgr *)userCookie;
    auto connMgr = reassemblyMgr->connMgr;
    // get a pointer to the connection manager

    // look for the connection in the connection manager
    auto iter = connMgr.find(connectionData.flowKey);

    // assuming it's a new connection
    if (iter == connMgr.end()) {
        // add it to the connection manager
        connMgr.insert(std::make_pair(connectionData.flowKey, TcpReassemblyData(connectionData.srcIP->getType() == pcpp::IPAddress::IPv4AddressType)));
    }
}

static void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData& connectionData, pcpp::TcpReassembly::ConnectionEndReason reason, void *userCookie)
{
    TcpReassemblyMgr *reassemblyMgr = (TcpReassemblyMgr *)userCookie;
    auto connMgr = reassemblyMgr->connMgr;
    // get a pointer to the connection manager

    // find the connection in the connection manager by the flow key
    auto iter = connMgr.find(connectionData.flowKey);

    // connection wasn't found, we didn't track
    if (iter == connMgr.end())
        return;

    // remove the connection from the connection manager
    connMgr.erase(iter);
}

TcpDnsReassembly::TcpDnsReassembly(TcpReassemblyMgr::process_dns_msg_cb process_dns_handler)
    : _reassemblyMgr()
{

    auto tcpReassemblyMsgReadyCallback = [](int sideIndex, const pcpp::TcpStreamData &tcpData, void *userCookie) {
        // extract the connection manager from the user cookie
        TcpReassemblyMgr *reassemblyMgr = (TcpReassemblyMgr *)userCookie;
        auto connMgr = reassemblyMgr->connMgr;
        auto flowKey = tcpData.getConnectionData().flowKey;

        // check if this flow already appears in the connection manager. If not add it
        auto iter = connMgr.find(flowKey);

        // if not tracking connection, and it's DNS, then start tracking.
        if (iter == connMgr.end() && (pcpp::DnsLayer::isDnsPort(tcpData.getConnectionData().srcPort) || pcpp::DnsLayer::isDnsPort(tcpData.getConnectionData().dstPort))) {
            connMgr.insert(std::make_pair(flowKey, TcpReassemblyData(tcpData.getConnectionData().srcIP->getType() == pcpp::IPAddress::IPv4AddressType)));
            iter = connMgr.find(tcpData.getConnectionData().flowKey);
        }
        else {
            // not tracking
            return;
        }

        int side(0);

        // if this messages comes on a different side than previous message seen on this connection
        if (sideIndex != iter->second.curSide) {
            // count number of message in each side
//            iter->second.numOfMessagesFromSide[sideIndex]++;

            // set side index as the current active side
            iter->second.curSide = sideIndex;
        }

        // count number of packets and bytes in each side of the connection
//        iter->second.numOfDataPackets[sideIndex]++;
//        iter->second.bytesFromSide[sideIndex] += (int)tcpData.getDataLength();

        pcpp::ProtocolType l3Type(iter->second.l3Type);

        auto malformed_data = []() {
            //            std::cerr << "malformed\n";
        };
        auto got_dns_message = [reassemblyMgr, sideIndex, l3Type, flowKey, tcpData](std::unique_ptr<const char[]> data,
                                   size_t size) {
            pcpp::Packet dnsRequest;
            pcpp::DnsLayer dnsLayer((uint8_t *)data.get(), size, nullptr, &dnsRequest);
            auto dir = (sideIndex == 0) ? pktvisor::fromHost : pktvisor::toHost;
            reassemblyMgr->process_dns_handler(&dnsLayer, dir, l3Type, flowKey, tcpData.getConnectionData().endTime);
        };
        if (!iter->second.dnsSession[side].get()) {
            iter->second.dnsSession[side] = std::make_shared<TcpDnsSession>(malformed_data, got_dns_message);
        }
        iter->second.dnsSession[side]->receive_data((char *)tcpData.getData(), tcpData.getDataLength());
    };

    _reassemblyMgr.process_dns_handler = process_dns_handler;
    _tcpReassembly = std::make_shared<pcpp::TcpReassembly>(
        tcpReassemblyMsgReadyCallback,
        &_reassemblyMgr,
        tcpReassemblyConnectionStartCallback,
        tcpReassemblyConnectionEndCallback);
}

}
