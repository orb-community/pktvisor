#ifndef PKTVISORD_PCAPINPUTSTREAM_H
#define PKTVISORD_PCAPINPUTSTREAM_H

#include "InputStream.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#include <IpAddress.h>
#include <PcapLiveDeviceList.h>
#include <TcpReassembly.h>
#include <UdpLayer.h>
#pragma GCC diagnostic pop
#include <functional>
#include <memory>
#include <sigslot/signal.hpp>
#include <unordered_map>
#include <vector>

namespace pktvisor {
namespace input {
namespace pcap {

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

enum PacketDirection { toHost,
    fromHost,
    unknown };

class TcpSessionData final
{
public:
    using malformed_data_cb = std::function<void()>;
    using got_data_cb = std::function<void(std::unique_ptr<char[]> data, size_t size)>;

    TcpSessionData(
        malformed_data_cb malformed_data_handler,
        got_data_cb got_data_handler);

    virtual void receive_data(const char data[], size_t len);

private:
    std::string _buffer;
    malformed_data_cb _malformed_data;
    got_data_cb _got_msg;
};

struct TcpReassemblyData {

    std::shared_ptr<TcpSessionData> _sessionData[2];

    // a flag indicating on which side was the latest message on this connection
    int curSide;
    pcpp::ProtocolType l3Type;

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
        curSide = -1;
        l3Type = pcpp::UnknownProtocol;
    }
};

struct TcpReassemblyMgr {

    using process_msg_cb = std::function<void(PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowKey, timespec stamp)>;

    process_msg_cb process_msg_handler;

    typedef std::map<uint32_t, TcpReassemblyData> TcpReassemblyConnMgr;

    TcpReassemblyConnMgr connMgr;
};

class TcpMsgReassembly
{
public:
    TcpMsgReassembly(TcpReassemblyMgr::process_msg_cb process_msg_handler);

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

private:
    IPv4subnetList hostIPv4;
    IPv6subnetList hostIPv6;
    std::unique_ptr<TcpMsgReassembly> _tcpReassembly;
    pcpp::PcapLiveDevice *_pcapDevice;

    bool _singleSummary = false;
    bool _pcapFile = false;

protected:
    void onGotMessage(PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowKey, timespec stamp);

    void openPcap(std::string fileName, std::string bpfFilter = "");
    void openIface(std::string bpfFilter = "");
    void getHostsFromIface();

public:
    PcapInputStream(const std::string &name);
    ~PcapInputStream();

    void start() override;
    void stop() override;

    // public so it can be called from a static callback method, required by PcapPlusPlus
    void processRawPacket(pcpp::RawPacket *rawPacket);

    // handler functionality
    sigslot::signal<pcpp::Packet &, PacketDirection, pcpp::ProtocolType, pcpp::ProtocolType, timespec> packet_signal;
    sigslot::signal<pcpp::UdpLayer &, PacketDirection, pcpp::ProtocolType, uint32_t, timespec> udp_signal;

    size_t consumer_count() override
    {
        return packet_signal.slot_count() + udp_signal.slot_count();
    }
};

}
}
}

#endif //PKTVISORD_PCAPINPUTSTREAM_H
