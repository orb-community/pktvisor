#ifndef PKTVISORD_PCAPINPUTSTREAM_H
#define PKTVISORD_PCAPINPUTSTREAM_H

#include "InputStream.h"
#include <IpAddress.h>
#include <PcapLiveDeviceList.h>
#include <TcpReassembly.h>
#include <concurrentqueue/blockingconcurrentqueue.h>
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>

namespace pktvisor {

// FIXME
class DnsLayer;

namespace input {

// list of subnets we count as "host" to determine direction of packets
struct IPv4subnet {
    pcpp::IPv4Address address;
    pcpp::IPv4Address mask;
    IPv4subnet(const pcpp::IPv4Address &a, const pcpp::IPv4Address &m)
        : address(a)
        , mask(m)
    {
    }
};
struct IPv6subnet {
    pcpp::IPv6Address address;
    uint8_t mask;
    IPv6subnet(const pcpp::IPv6Address &a, int m)
        : address(a)
        , mask(m)
    {
    }
};
typedef std::vector<IPv4subnet> IPv4subnetList;
typedef std::vector<IPv6subnet> IPv6subnetList;

enum Direction { toHost,
    fromHost,
    unknown };

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

    using process_dns_msg_cb = std::function<void(pktvisor::DnsLayer *, Direction dir, pcpp::ProtocolType l3, uint32_t flowKey, timespec stamp)>;

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

class PcapInputStream : public pktvisor::InputStream
{
public:
    typedef moodycamel::BlockingConcurrentQueue<std::shared_ptr<const pcpp::Packet>> ConcurrentQueue;
    //    typedef moodycamel::ProducerToken QueueToken;
    //    typedef std::pair<std::unique_ptr<ConcurrentQueue>, QueueToken> ConcurrentQueuePair;
    //    typedef std::pair<ConcurrentQueue *, QueueToken> ConcurrentQueueConsumerPair;

private:
    IPv4subnetList hostIPv4;
    IPv6subnetList hostIPv6;
    std::unique_ptr<TcpDnsReassembly> _tcpReassembly;
    pcpp::PcapLiveDevice *_pcapDevice;

    std::unordered_map<std::string, ConcurrentQueue *> _queues;

protected:
    void onGotDnsMessage(pktvisor::DnsLayer *dnsLayer, Direction dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowKey, timespec stamp);

    void openPcap(std::string fileName, std::string bpfFilter = "");
    void openIface(std::string bpfFilter = "");
    void getHostsFromIface();

public:
    PcapInputStream(const std::string &name);
    ~PcapInputStream();

    void start() override;
    void stop() override;

    ConcurrentQueue *register_consumer(const std::string &name);

    // public so it can be called from a static callback method
    void processRawPacket(pcpp::RawPacket *rawPacket);
};

}
}

#endif //PKTVISORD_PCAPINPUTSTREAM_H
