#include "DnsStreamHandler.h"
#include "GeoDB.h"
#include "dns.h"
#include "utils.h"
#include <Corrade/Utility/Debug.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#pragma GCC diagnostic pop
#include <arpa/inet.h>
#include <datasketches/datasketches/cpc/cpc_union.hpp>

namespace pktvisor::handler::dns {

DnsStreamHandler::DnsStreamHandler(const std::string &name, PcapInputStream *stream, uint periods, int deepSampleRate)
    : pktvisor::StreamMetricsHandler<DnsMetricsManager>(name, periods, deepSampleRate)
    , _stream(stream)
{
    assert(stream);
}

void DnsStreamHandler::start()
{
    if (_running) {
        return;
    }

    _pkt_udp_connection = _stream->udp_signal.connect(&DnsStreamHandler::process_udp_packet_cb, this);
    _start_tstamp_connection = _stream->start_tstamp_signal.connect(&DnsStreamHandler::set_initial_tstamp, this);

    _running = true;
}

void DnsStreamHandler::stop()
{
    if (!_running) {
        return;
    }

    _pkt_udp_connection.disconnect();
    _start_tstamp_connection.disconnect();

    _running = false;
}

DnsStreamHandler::~DnsStreamHandler()
{
}

// callback from input module
void DnsStreamHandler::process_udp_packet_cb(pcpp::UdpLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp)
{
    _metrics->process_udp_packet(payload, dir, l3, flowkey, stamp);
}

void DnsStreamHandler::toJSON(json &j, uint64_t period, bool merged)
{
    if (merged) {
        _metrics->toJSONMerged(j["dns"], period);
    } else {
        _metrics->toJSONSingle(j["dns"], period);
    }
}
void DnsStreamHandler::set_initial_tstamp(timespec stamp)
{
    _metrics->set_initial_tstamp(stamp);
}
json DnsStreamHandler::info_json() const
{
    json result;
    return result;
}

void DnsMetricsBucket::specialized_merge(const AbstractMetricsBucket &o)
{
    // static because caller guarantees only our own bucket type
    const auto &other = static_cast<const DnsMetricsBucket &>(o);
}

void DnsMetricsBucket::toJSON(json &j) const
{

    const double fractions[4]{0.50, 0.90, 0.95, 0.99};
}

// the main bucket analysis
void DnsMetricsBucket::process_udp_packet(bool deep, pcpp::UdpLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp)
{

    std::unique_lock w_lock(_mutex);

    if (!deep) {
        return;
    }

    auto srcPort = ntohs(payload.getUdpHeader()->portSrc);
    auto dstPort = ntohs(payload.getUdpHeader()->portDst);
    // track whichever port wasn't a DNS port (in and out)
    if (DnsLayer::isDnsPort(dstPort)) {
        _dns_topUDPPort.update(srcPort);
    } else if (DnsLayer::isDnsPort(srcPort)) {
        _dns_topUDPPort.update(dstPort);
    }
}

// the general metrics manager entry point
void DnsMetricsManager::process_udp_packet(pcpp::UdpLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp)
{
    // base event
    new_event(stamp);
    // process in the "live" bucket
    _metricBuckets.back()->process_udp_packet(_shouldDeepSample, payload, dir, l3, flowkey, stamp);
}

}