#include "DnsStreamHandler.h"
#include "GeoDB.h"
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
void DnsStreamHandler::process_udp_packet_cb(pcpp::Packet &payload, PacketDirection dir, pcpp::ProtocolType l3, uint32_t flowkey, timespec stamp)
{
    pcpp::UdpLayer *udpLayer = payload.getLayerOfType<pcpp::UdpLayer>();
    assert(udpLayer);

    uint16_t port{0};
    auto dst_port = ntohs(udpLayer->getUdpHeader()->portDst);
    auto src_port = ntohs(udpLayer->getUdpHeader()->portSrc);
    if (DnsLayer::isDnsPort(dst_port)) {
        port = dst_port;
    } else if (DnsLayer::isDnsPort(src_port)) {
        port = src_port;
    }
    if (port) {
        DnsLayer dnsLayer(udpLayer, &payload);
        _metrics->process_dns_layer(dnsLayer, dir, l3, pcpp::UDP, flowkey, port, stamp);
    }
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
void DnsMetricsBucket::process_dns_layer(bool deep, DnsLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowkey, uint16_t port, timespec stamp)
{

    std::unique_lock lock(_mutex);

    if (l3 == pcpp::IPv6) {
        _DNS_IPv6++;
    }

    if (l4 == pcpp::TCP) {
        _DNS_TCP++;
    }

    // only count response codes on responses (not queries)
    if (payload.getDnsHeader()->queryOrResponse == QR::response) {
        _DNS_replies++;
        switch (payload.getDnsHeader()->responseCode) {
        case NoError:
            _DNS_NOERROR++;
            break;
        case SrvFail:
            _DNS_SRVFAIL++;
            break;
        case NXDomain:
            _DNS_NX++;
            break;
        case Refused:
            _DNS_REFUSED++;
            break;
        }
    } else {
        _DNS_queries++;
    }

    if (!deep) {
        return;
    }

    payload.parseResources(true);

    if (payload.getDnsHeader()->queryOrResponse == response) {
        _dns_topRCode.update(payload.getDnsHeader()->responseCode);
    }

    auto query = payload.getFirstQuery();
    if (query) {

        auto name = query->getName();

        _dns_qnameCard.update(name);
        _dns_topQType.update(query->getDnsType());

        if (payload.getDnsHeader()->queryOrResponse == response) {
            switch (payload.getDnsHeader()->responseCode) {
            case SrvFail:
                _dns_topSRVFAIL.update(name);
                break;
            case NXDomain:
                _dns_topNX.update(name);
                break;
            case Refused:
                _dns_topREFUSED.update(name);
                break;
            }
        }

        auto aggDomain = aggregateDomain(name);
        _dns_topQname2.update(std::string(aggDomain.first));
        if (aggDomain.second.size()) {
            _dns_topQname3.update(std::string(aggDomain.second));
        }
    }

    _dns_topUDPPort.update(port);
}

// the general metrics manager entry point (both UDP and TCP)
void DnsMetricsManager::process_dns_layer(DnsLayer &payload, PacketDirection dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4, uint32_t flowkey, uint16_t port, timespec stamp)
{
    // base event
    new_event(stamp);
    // process in the "live" bucket
    _metricBuckets.back()->process_dns_layer(_shouldDeepSample, payload, dir, l3, l4, flowkey, port, stamp);
}

}