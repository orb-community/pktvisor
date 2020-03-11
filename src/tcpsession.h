#pragma once

#include <DnsLayer.h>
#include <TcpReassembly.h>

#include <functional>
#include <memory>

#include "pktvisor.h"

namespace pktvisor {

class TcpDnsSession final
{
public:
    using malformed_data_cb = std::function<void()>;
    using got_dns_msg_cb = std::function<void(std::unique_ptr<char[]> data, size_t size)>;

    TcpDnsSession(
        malformed_data_cb malformed_data_handler,
        got_dns_msg_cb got_dns_msg_handler);

    virtual void receive_data(const char data[], size_t len);

private:
    std::string _buffer;
    malformed_data_cb _malformed_data;
    got_dns_msg_cb _got_dns_msg;
};

struct TcpReassemblyData {

    std::shared_ptr<TcpDnsSession> dnsSession[2];

    // a flag indicating on which side was the latest message on this connection
    int curSide;
    pcpp::ProtocolType l3Type;

    // stats data: num of data packets on each side, bytes seen on each side and messages seen on each side
//    int numOfDataPackets[2];
//    int numOfMessagesFromSide[2];
//    int bytesFromSide[2];

    /**
	 * the default c'tor
	 */
    TcpReassemblyData(bool isIPv4)
    {
        clear();
        (isIPv4) ? l3Type = pcpp::IPv4 : l3Type = pcpp::IPv6;
    }

    /**
	 * The default d'tor
	 */
    ~TcpReassemblyData()
    {
    }

    /**
	 * Clear all data (put 0, false or NULL - whatever relevant for each field)
	 */
    void clear()
    {
//        numOfDataPackets[0] = 0;
//        numOfDataPackets[1] = 0;
//        numOfMessagesFromSide[0] = 0;
//        numOfMessagesFromSide[1] = 0;
//        bytesFromSide[0] = 0;
//        bytesFromSide[1] = 0;
        curSide = -1;
        l3Type = pcpp::UnknownProtocol;
    }
};

struct TcpReassemblyMgr {

    using process_dns_msg_cb = std::function<void(pcpp::DnsLayer *, Direction dir, pcpp::ProtocolType l3, uint32_t flowKey, timeval stamp)>;

    process_dns_msg_cb process_dns_handler;

    typedef std::map<uint32_t, TcpReassemblyData> TcpReassemblyConnMgr;

    TcpReassemblyConnMgr connMgr;
};

class TcpDnsReassembly
{
public:
    TcpDnsReassembly(TcpReassemblyMgr::process_dns_msg_cb process_dns_handler);

    std::shared_ptr<pcpp::TcpReassembly> getTcpReassembly()
    {
        return _tcpReassembly;
    }

private:
    TcpReassemblyMgr _reassemblyMgr;
    std::shared_ptr<pcpp::TcpReassembly> _tcpReassembly;
};

}
