#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <Packet.h>
#include <UdpLayer.h>
#include <chrono>
#include <datasketches/datasketches/cpc/cpc_union.hpp>
#include <sstream>

#include <math.h>
#include <arpa/inet.h>

#include "dns/dns.h"
#include "metrics.h"
#include "utils.h"

namespace pktvisor {

Metrics::Metrics(MetricsMgr& mmgr) : _mmgr(mmgr)
{
    gettimeofday(&_bucketTS, nullptr);

    // lock for write
    std::unique_lock lock(_sketchMutex);
    _sketches = std::make_unique<Sketches>();
}

// merge two Metrics objects
void Metrics::merge(Metrics &other)
{

    _numSamples += other._numSamples;

    _numPackets += other._numPackets;
    _numPackets_UDP += other._numPackets_UDP;
    _numPackets_TCP += other._numPackets_TCP;
    _numPackets_OtherL4 += other._numPackets_OtherL4;
    _numPackets_IPv6 += other._numPackets_IPv6;
    _numPackets_in += other._numPackets_in;
    _numPackets_out += other._numPackets_out;

    _DNS_total += other._DNS_total;
    _DNS_xacts_total += other._DNS_xacts_total;
    _DNS_xacts_in += other._DNS_xacts_in;
    _DNS_xacts_out += other._DNS_xacts_out;
    _DNS_queries += other._DNS_queries;
    _DNS_replies += other._DNS_replies;
    _DNS_TCP += other._DNS_TCP;
    _DNS_IPv6 += other._DNS_IPv6;
    _DNS_NX += other._DNS_NX;
    _DNS_REFUSED += other._DNS_REFUSED;
    _DNS_SRVFAIL += other._DNS_SRVFAIL;
    _DNS_NOERROR += other._DNS_NOERROR;

    // lock me for for write, other for read
    std::unique_lock w_lock(_sketchMutex);
    std::shared_lock r_lock(other._sketchMutex);
    std::unique_lock w_lock_r(_rateSketchMutex);
    std::shared_lock r_lock_r(other._rateSketchMutex);

    _rateSketches.net_rateIn.merge(other._rateSketches.net_rateIn);
    _rateSketches.net_rateOut.merge(other._rateSketches.net_rateOut);

    _sketches->_dnsXactFromTimeUs.merge(other._sketches->_dnsXactFromTimeUs);
    _sketches->_dnsXactToTimeUs.merge(other._sketches->_dnsXactToTimeUs);

    datasketches::cpc_union merge_srcIPCard;
    merge_srcIPCard.update(_sketches->_net_srcIPCard);
    merge_srcIPCard.update(other._sketches->_net_srcIPCard);
    _sketches->_net_srcIPCard = merge_srcIPCard.get_result();

    datasketches::cpc_union merge_dstIPCard;
    merge_dstIPCard.update(_sketches->_net_dstIPCard);
    merge_dstIPCard.update(other._sketches->_net_dstIPCard);
    _sketches->_net_dstIPCard = merge_dstIPCard.get_result();

    datasketches::cpc_union merge_qnameCard;
    merge_qnameCard.update(_sketches->_dns_qnameCard);
    merge_qnameCard.update(other._sketches->_dns_qnameCard);
    _sketches->_dns_qnameCard = merge_qnameCard.get_result();

    _sketches->_dns_topQname2.merge(other._sketches->_dns_topQname2);
    _sketches->_dns_topQname3.merge(other._sketches->_dns_topQname3);
    _sketches->_dns_topNX.merge(other._sketches->_dns_topNX);
    _sketches->_dns_topREFUSED.merge(other._sketches->_dns_topREFUSED);
    _sketches->_dns_topSRVFAIL.merge(other._sketches->_dns_topSRVFAIL);
    _sketches->_dns_topUDPPort.merge(other._sketches->_dns_topUDPPort);
    _sketches->_net_topIPv4.merge(other._sketches->_net_topIPv4);
    _sketches->_net_topIPv6.merge(other._sketches->_net_topIPv6);
    _sketches->_dns_topQType.merge(other._sketches->_dns_topQType);
    _sketches->_dns_topRCode.merge(other._sketches->_dns_topRCode);
    _sketches->_dns_slowXactIn.merge(other._sketches->_dns_slowXactIn);
    _sketches->_dns_slowXactOut.merge(other._sketches->_dns_slowXactOut);
    _sketches->_net_topGeoLoc.merge(other._sketches->_net_topGeoLoc);
    _sketches->_net_topASN.merge(other._sketches->_net_topASN);
}

void Metrics::newDNSPacket(pktvisor::DnsLayer *dns, Direction dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4)
{

    _DNS_total++;

    if (l3 == pcpp::IPv6) {
        _DNS_IPv6++;
    }

    if (l4 == pcpp::TCP) {
        _DNS_TCP++;
    }

    // only count response codes on responses (not queries)
    if (dns->getDnsHeader()->queryOrResponse == response) {
        _DNS_replies++;
        switch (dns->getDnsHeader()->responseCode) {
        case 0:
            _DNS_NOERROR++;
            break;
        case 2:
            _DNS_SRVFAIL++;
            break;
        case 3:
            _DNS_NX++;
            break;
        case 5:
            _DNS_REFUSED++;
            break;
        }
    } else {
        _DNS_queries++;
    }

    // sampler
    if (!_mmgr.shouldDeepSample()) {
        return;
    }

    dns->parseResources();

    // lock for write
    std::unique_lock lock(_sketchMutex);

    if (dns->getDnsHeader()->queryOrResponse == response) {
        _sketches->_dns_topRCode.update(dns->getDnsHeader()->responseCode);
    }

    auto query = dns->getFirstQuery();
    if (query) {

        auto name = query->getName();

        _sketches->_dns_qnameCard.update(name);
        _sketches->_dns_topQType.update(query->getDnsType());

        if (dns->getDnsHeader()->queryOrResponse == response) {
            switch (dns->getDnsHeader()->responseCode) {
            case 2:
                _sketches->_dns_topSRVFAIL.update(name);
                break;
            case 3:
                _sketches->_dns_topNX.update(name);
                break;
            case 5:
                _sketches->_dns_topREFUSED.update(name);
                break;
            }
        }

        auto aggDomain = aggregateDomain(name);
        _sketches->_dns_topQname2.update(std::string(aggDomain.first));
        if (aggDomain.second.size()) {
            _sketches->_dns_topQname3.update(std::string(aggDomain.second));
        }
    }
}

void Metrics::newDNSXact(pktvisor::DnsLayer *dns, Direction dir, DnsTransaction xact)
{

    // sampler
    bool chosen = _mmgr.shouldDeepSample();

    _DNS_xacts_total++;

    uint64_t xactTime = ((xact.totalTS.tv_sec * 1000000000L) + xact.totalTS.tv_nsec) / 1000; // nanoseconds to microseconds
    // dir is the direction of the last packet, meaning the reply so from a transaction perspective
    // we look at it from the direction of the query, so the opposite side than we have here
    float to90th = 0.0;
    float from90th = 0.0;
    uint64_t sample_threshold = 10;

    if (chosen) {
        // lock for write
        std::unique_lock lock(_sketchMutex);
    }

    if (dir == toHost) {
        _DNS_xacts_out++;
        if (chosen) {
            _sketches->_dnsXactFromTimeUs.update(xactTime);
            // wait for N samples
            if (_sketches->_dnsXactFromTimeUs.get_n() > sample_threshold) {
                from90th = _sketches->_dnsXactFromTimeUs.get_quantile(0.90);
            }
        }
    } else if (dir == fromHost) {
        _DNS_xacts_in++;
        if (chosen) {
            _sketches->_dnsXactToTimeUs.update(xactTime);
            // wait for N samples
            if (_sketches->_dnsXactToTimeUs.get_n() > sample_threshold) {
                to90th = _sketches->_dnsXactToTimeUs.get_quantile(0.90);
            }
        }
    }

    if (chosen) {
        auto query = dns->getFirstQuery();
        if (query) {
            auto name = query->getName();
            // see comment in MetricsMgr::newDNSxact on direction and why "toHost" is used with "from"
            if (dir == toHost && from90th > 0 && xactTime >= from90th) {
                _sketches->_dns_slowXactOut.update(name);
            } else if (dir == fromHost && to90th > 0 && xactTime >= to90th) {
                _sketches->_dns_slowXactIn.update(name);
            }
        }
    }

}

void MetricsMgr::newDNSXact(pktvisor::DnsLayer *dns, Direction dir, DnsTransaction xact)
{
    _metrics.back()->newDNSXact(dns, dir, xact);
}

void MetricsMgr::newDNSPacket(pktvisor::DnsLayer *dns, Direction dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4)
{
    _metrics.back()->newDNSPacket(dns, dir, l3, l4);
}

void Metrics::newPacket(const pcpp::Packet &packet, pcpp::ProtocolType l3, pcpp::ProtocolType l4, Direction dir)
{

    _numPackets++;
    if (_mmgr.shouldDeepSample()) {
        _numSamples++;
    }

    switch (dir) {
    case fromHost:
        _numPackets_out++;
        break;
    case toHost:
        _numPackets_in++;
        break;
    case unknown:
        break;
    }

    switch (l3) {
    case pcpp::IPv6:
        _numPackets_IPv6++;
        break;
    default:
        break;
    }

    switch (l4) {
    case pcpp::UDP:
        _numPackets_UDP++;
        break;
    case pcpp::TCP:
        _numPackets_TCP++;
        break;
    default:
        _numPackets_OtherL4++;
        break;
    }

    // sampler
    if (!_mmgr.shouldDeepSample()) {
        return;
    }

    // lock for write
    std::unique_lock lock(_sketchMutex);

#ifdef MMDB_ENABLE
    const GeoDB* geoCityDB = _mmgr.getGeoCityDB();
    const GeoDB* geoASNDB = _mmgr.getGeoASNDB();
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
#endif

    auto IP4layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    auto IP6layer = packet.getLayerOfType<pcpp::IPv6Layer>();
    if (IP4layer) {
        if (dir == toHost) {
            _sketches->_net_srcIPCard.update(IP4layer->getSrcIpAddress().toInt());
            _sketches->_net_topIPv4.update(IP4layer->getSrcIpAddress().toInt());
#ifdef MMDB_ENABLE
            if (IPv4tosockaddr(IP4layer->getSrcIpAddress(), &sa4)) {
                if (geoCityDB) {
                    _sketches->_net_topGeoLoc.update(geoCityDB->getGeoLocString((struct sockaddr*)&sa4));
                }
                if (geoASNDB) {
                    _sketches->_net_topASN.update(geoASNDB->getASNString((struct sockaddr*)&sa4));
                }
            }
#endif
        } else if (dir == fromHost) {
            _sketches->_net_dstIPCard.update(IP4layer->getDstIpAddress().toInt());
            _sketches->_net_topIPv4.update(IP4layer->getDstIpAddress().toInt());
#ifdef MMDB_ENABLE
            if (IPv4tosockaddr(IP4layer->getDstIpAddress(), &sa4)) {
                if (geoCityDB) {
                    _sketches->_net_topGeoLoc.update(geoCityDB->getGeoLocString((struct sockaddr*)&sa4));
                }
                if (geoASNDB) {
                    _sketches->_net_topASN.update(geoASNDB->getASNString((struct sockaddr*)&sa4));
                }
            }
#endif
        }
    } else if (IP6layer) {
        if (dir == toHost) {
            _sketches->_net_srcIPCard.update((void *)IP6layer->getSrcIpAddress().toBytes(), 16);
            _sketches->_net_topIPv6.update(IP6layer->getSrcIpAddress().toString());
#ifdef MMDB_ENABLE
            if (IPv6tosockaddr(IP6layer->getSrcIpAddress(), &sa6)) {
                if (geoCityDB) {
                    _sketches->_net_topGeoLoc.update(geoCityDB->getGeoLocString((struct sockaddr*)&sa6));
                }
                if (geoASNDB) {
                    _sketches->_net_topASN.update(geoASNDB->getASNString((struct sockaddr*)&sa6));
                }
            }
#endif
        } else if (dir == fromHost) {
            _sketches->_net_dstIPCard.update((void *)IP6layer->getDstIpAddress().toBytes(), 16);
            _sketches->_net_topIPv6.update(IP6layer->getDstIpAddress().toString());
#ifdef MMDB_ENABLE
            if (IPv6tosockaddr(IP6layer->getDstIpAddress(), &sa6)) {
                if (geoCityDB) {
                    _sketches->_net_topGeoLoc.update(geoCityDB->getGeoLocString((struct sockaddr*)&sa6));
                }
                if (geoASNDB) {
                    _sketches->_net_topASN.update(geoASNDB->getASNString((struct sockaddr*)&sa6));
                }
            }
#endif
        }
    }

    auto UDPLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (UDPLayer) {
        auto srcPort = ntohs(UDPLayer->getUdpHeader()->portSrc);
        auto dstPort = ntohs(UDPLayer->getUdpHeader()->portDst);
        // track whichever port wasn't a DNS port (in and out)
        if (pktvisor::DnsLayer::isDnsPort(dstPort)) {
            _sketches->_dns_topUDPPort.update(srcPort);
        } else if (pktvisor::DnsLayer::isDnsPort(srcPort)) {
            _sketches->_dns_topUDPPort.update(dstPort);
        }
    }
}

void Metrics::assignRateSketches(const std::shared_ptr<InstantRateMetrics> rm)
{
    // lock for write
    std::unique_lock lock(_rateSketchMutex);
    _rateSketches.net_rateIn = rm->_rate_in.getQuantileCopy();
    _rateSketches.net_rateOut = rm->_rate_out.getQuantileCopy();
}

void MetricsMgr::_periodShift()
{

    // copy instant rate results into bucket before shift
    _metrics.back()->assignRateSketches(_instantRates);
    // reset instant rate quantiles so they are accurate for next minute bucket
    _instantRates->resetQuantiles();

    // add new bucket
    _metrics.emplace_back(std::make_unique<Metrics>(*this));
    if (_metrics.size() > _numPeriods) {
        // if we're at our period history length, pop the oldest
        _metrics.pop_front();
    }
}

void MetricsMgr::setInitialShiftTS() {
    timespec_get(&_lastShiftTS, TIME_UTC);
}

void MetricsMgr::setInitialShiftTS(const pcpp::Packet &packet) {
    _lastShiftTS.tv_sec = packet.getRawPacketReadOnly()->getPacketTimeStamp().tv_sec;
    _lastShiftTS.tv_nsec = packet.getRawPacketReadOnly()->getPacketTimeStamp().tv_nsec;
}

void MetricsMgr::newPacket(const pcpp::Packet &packet, QueryResponsePairMgr &pairMgr, pcpp::ProtocolType l4, Direction dir, pcpp::ProtocolType l3)
{
    // at each new packet, we determine if we are sampling, to limit collection of more detailed (expensive) statistics
    _shouldDeepSample = true;
    if (_deepSampleRate != 100) {
        _shouldDeepSample = (_rng.uniform(0, 100) <= _deepSampleRate);
    }
    if (!_singleSummaryMode) {
        // use packet timestamps to track when PERIOD_SEC passes so we don't have to hit system clock
        auto pkt_ts = packet.getRawPacketReadOnly()->getPacketTimeStamp();
        if (pkt_ts.tv_sec - _lastShiftTS.tv_sec > MetricsMgr::PERIOD_SEC) {
            _periodShift();
            _lastShiftTS.tv_sec = pkt_ts.tv_sec;
            pairMgr.purgeOldTransactions(pkt_ts);
            _openDnsTransactionCount = pairMgr.getOpenTransactionCount();
        }
        switch (dir) {
        case fromHost:
            _instantRates->_rate_out.incCounter();
            break;
        case toHost:
            _instantRates->_rate_in.incCounter();
            break;
        case unknown:
            break;
        }
    }
    _metrics.back()->newPacket(packet, l3, l4, dir);
}

void Metrics::toJSON(nlohmann::json &j, const std::string &key)
{

    // lock for read
    std::shared_lock lock_sketch(_sketchMutex);
    std::shared_lock lock_rate(_rateSketchMutex);

    j[key]["packets"]["deep_samples"] = _numSamples.load();

    j[key]["packets"]["total"] = _numPackets.load();
    j[key]["packets"]["udp"] = _numPackets_UDP.load();
    j[key]["packets"]["tcp"] = _numPackets_TCP.load();
    j[key]["packets"]["other_l4"] = _numPackets_OtherL4.load();
    j[key]["packets"]["ipv4"] = _numPackets - _numPackets_IPv6;
    j[key]["packets"]["ipv6"] = _numPackets_IPv6.load();
    j[key]["packets"]["in"] = _numPackets_in.load();
    j[key]["packets"]["out"] = _numPackets_out.load();

    j[key]["packets"]["cardinality"]["src_ips_in"] = lround(_sketches->_net_srcIPCard.get_estimate());
    j[key]["packets"]["cardinality"]["dst_ips_out"] = lround(_sketches->_net_dstIPCard.get_estimate());

    const double fractions[4]{0.50, 0.90, 0.95, 0.99};
    auto quantiles = _rateSketches.net_rateIn.get_quantiles(fractions, 4);
    if (quantiles.size()) {
        j[key]["packets"]["rates"]["pps_in"]["p50"] = quantiles[0];
        j[key]["packets"]["rates"]["pps_in"]["p90"] = quantiles[1];
        j[key]["packets"]["rates"]["pps_in"]["p95"] = quantiles[2];
        j[key]["packets"]["rates"]["pps_in"]["p99"] = quantiles[3];
    }
    quantiles = _rateSketches.net_rateOut.get_quantiles(fractions, 4);
    if (quantiles.size()) {
        j[key]["packets"]["rates"]["pps_out"]["p50"] = quantiles[0];
        j[key]["packets"]["rates"]["pps_out"]["p90"] = quantiles[1];
        j[key]["packets"]["rates"]["pps_out"]["p95"] = quantiles[2];
        j[key]["packets"]["rates"]["pps_out"]["p99"] = quantiles[3];
    }

    j[key]["dns"]["wire_packets"]["total"] = _DNS_total.load();
    j[key]["dns"]["wire_packets"]["queries"] = _DNS_queries.load();
    j[key]["dns"]["wire_packets"]["replies"] = _DNS_replies.load();
    j[key]["dns"]["wire_packets"]["tcp"] = _DNS_TCP.load();
    j[key]["dns"]["wire_packets"]["udp"] = _DNS_total - _DNS_TCP;
    j[key]["dns"]["wire_packets"]["ipv4"] = _DNS_total - _DNS_IPv6;
    j[key]["dns"]["wire_packets"]["ipv6"] = _DNS_IPv6.load();
    j[key]["dns"]["wire_packets"]["nxdomain"] = _DNS_NX.load();
    j[key]["dns"]["wire_packets"]["refused"] = _DNS_REFUSED.load();
    j[key]["dns"]["wire_packets"]["srvfail"] = _DNS_SRVFAIL.load();
    j[key]["dns"]["wire_packets"]["noerror"] = _DNS_NOERROR.load();

    j[key]["dns"]["cardinality"]["qname"] = lround(_sketches->_dns_qnameCard.get_estimate());

    {
        j[key]["packets"]["top_ipv4"] = nlohmann::json::array();
        auto items = _sketches->_net_topIPv4.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j[key]["packets"]["top_ipv4"][i]["name"] = pcpp::IPv4Address(items[i].get_item()).toString();
            j[key]["packets"]["top_ipv4"][i]["estimate"] = items[i].get_estimate();
        }
    }

    {
        j[key]["packets"]["top_ipv6"] = nlohmann::json::array();
        auto items = _sketches->_net_topIPv6.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j[key]["packets"]["top_ipv6"][i]["name"] = items[i].get_item();
            j[key]["packets"]["top_ipv6"][i]["estimate"] = items[i].get_estimate();
        }
    }

    {
        j[key]["packets"]["top_geoLoc"] = nlohmann::json::array();
        auto items = _sketches->_net_topGeoLoc.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j[key]["packets"]["top_geoLoc"][i]["name"] = items[i].get_item();
            j[key]["packets"]["top_geoLoc"][i]["estimate"] = items[i].get_estimate();
        }
    }

    {
        j[key]["packets"]["top_ASN"] = nlohmann::json::array();
        auto items = _sketches->_net_topASN.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j[key]["packets"]["top_ASN"][i]["name"] = items[i].get_item();
            j[key]["packets"]["top_ASN"][i]["estimate"] = items[i].get_estimate();
        }
    }

    {
        j[key]["dns"]["top_udp_ports"] = nlohmann::json::array();
        auto items = _sketches->_dns_topUDPPort.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            std::stringstream keyBuf;
            keyBuf << items[i].get_item();
            j[key]["dns"]["top_udp_ports"][i]["name"] = keyBuf.str();
            j[key]["dns"]["top_udp_ports"][i]["estimate"] = items[i].get_estimate();
        }
    }

    j[key]["dns"]["xact"]["counts"]["total"] = _DNS_xacts_total.load();

    {
        j[key]["dns"]["xact"]["in"]["total"] = _DNS_xacts_in.load();
        j[key]["dns"]["xact"]["in"]["top_slow"] = nlohmann::json::array();
        auto items = _sketches->_dns_slowXactIn.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j[key]["dns"]["xact"]["in"]["top_slow"][i]["name"] = items[i].get_item();
            j[key]["dns"]["xact"]["in"]["top_slow"][i]["estimate"] = items[i].get_estimate();
        }
    }

    auto d_quantiles = _sketches->_dnsXactFromTimeUs.get_quantiles(fractions, 4);
    if (d_quantiles.size()) {
        j[key]["dns"]["xact"]["out"]["quantiles_us"]["p50"] = d_quantiles[0];
        j[key]["dns"]["xact"]["out"]["quantiles_us"]["p90"] = d_quantiles[1];
        j[key]["dns"]["xact"]["out"]["quantiles_us"]["p95"] = d_quantiles[2];
        j[key]["dns"]["xact"]["out"]["quantiles_us"]["p99"] = d_quantiles[3];
    }

    d_quantiles = _sketches->_dnsXactToTimeUs.get_quantiles(fractions, 4);
    if (d_quantiles.size()) {
        j[key]["dns"]["xact"]["in"]["quantiles_us"]["p50"] = d_quantiles[0];
        j[key]["dns"]["xact"]["in"]["quantiles_us"]["p90"] = d_quantiles[1];
        j[key]["dns"]["xact"]["in"]["quantiles_us"]["p95"] = d_quantiles[2];
        j[key]["dns"]["xact"]["in"]["quantiles_us"]["p99"] = d_quantiles[3];
    }

    {
        j[key]["dns"]["xact"]["out"]["total"] = _DNS_xacts_out.load();
        j[key]["dns"]["xact"]["out"]["top_slow"] = nlohmann::json::array();
        auto items = _sketches->_dns_slowXactOut.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j[key]["dns"]["xact"]["out"]["top_slow"][i]["name"] = items[i].get_item();
            j[key]["dns"]["xact"]["out"]["top_slow"][i]["estimate"] = items[i].get_estimate();
        }
    }

    {
        j[key]["dns"]["top_qname2"] = nlohmann::json::array();
        auto items = _sketches->_dns_topQname2.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j[key]["dns"]["top_qname2"][i]["name"] = items[i].get_item();
            j[key]["dns"]["top_qname2"][i]["estimate"] = items[i].get_estimate();
        }
    }

    {
        j[key]["dns"]["top_qname3"] = nlohmann::json::array();
        auto items = _sketches->_dns_topQname3.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j[key]["dns"]["top_qname3"][i]["name"] = items[i].get_item();
            j[key]["dns"]["top_qname3"][i]["estimate"] = items[i].get_estimate();
        }
    }

    {
        j[key]["dns"]["top_nxdomain"] = nlohmann::json::array();
        auto items = _sketches->_dns_topNX.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j[key]["dns"]["top_nxdomain"][i]["name"] = items[i].get_item();
            j[key]["dns"]["top_nxdomain"][i]["estimate"] = items[i].get_estimate();
        }
    }

    {
        j[key]["dns"]["top_refused"] = nlohmann::json::array();
        auto items = _sketches->_dns_topREFUSED.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j[key]["dns"]["top_refused"][i]["name"] = items[i].get_item();
            j[key]["dns"]["top_refused"][i]["estimate"] = items[i].get_estimate();
        }
    }

    {
        j[key]["dns"]["top_srvfail"] = nlohmann::json::array();
        auto items = _sketches->_dns_topSRVFAIL.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j[key]["dns"]["top_srvfail"][i]["name"] = items[i].get_item();
            j[key]["dns"]["top_srvfail"][i]["estimate"] = items[i].get_estimate();
        }
    }

    {
        j[key]["dns"]["top_rcode"] = nlohmann::json::array();
        auto items = _sketches->_dns_topRCode.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            if (DNS_RCODES.find(items[i].get_item()) != DNS_RCODES.end()) {
                j[key]["dns"]["top_rcode"][i]["name"] = DNS_RCODES[items[i].get_item()];
            } else {
                std::stringstream keyBuf;
                keyBuf << items[i].get_item();
                j[key]["dns"]["top_rcode"][i]["name"] = keyBuf.str();
            }
            j[key]["dns"]["top_rcode"][i]["estimate"] = items[i].get_estimate();
        }
    }

    {
        j[key]["dns"]["top_qtype"] = nlohmann::json::array();
        auto items = _sketches->_dns_topQType.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            if (DNS_QTYPES.find(items[i].get_item()) != DNS_QTYPES.end()) {
                j[key]["dns"]["top_qtype"][i]["name"] = DNS_QTYPES[items[i].get_item()];
            } else {
                std::stringstream keyBuf;
                keyBuf << items[i].get_item();
                j[key]["dns"]["top_qtype"][i]["name"] = keyBuf.str();
            }
            j[key]["dns"]["top_qtype"][i]["estimate"] = items[i].get_estimate();
        }
    }
}

std::string MetricsMgr::getAppMetrics()
{
    nlohmann::json j;
    j["app"]["version"] = PKTVISOR_VERSION_NUM;
    j["app"]["deep_sample_rate_pct"] = _deepSampleRate;
    j["app"]["periods"] = _numPeriods;
    j["app"]["single_summary"] = _singleSummaryMode;
    j["app"]["up_time_min"] = float(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - _startTime).count()) / 60;

    j["dns"]["xact"]["open"] = _openDnsTransactionCount;

    return j.dump(-1, ' ', true, nlohmann::json::error_handler_t::replace);
}

std::string MetricsMgr::getInstantRates()
{

    nlohmann::json j;
    j["packets"]["in"] = _instantRates->_rate_in.getRate();
    j["packets"]["out"] = _instantRates->_rate_out.getRate();
    return j.dump(-1, ' ', true, nlohmann::json::error_handler_t::replace);
}

std::string MetricsMgr::getMetrics(uint64_t period)
{

    nlohmann::json j;

    if (_singleSummaryMode) {
        period = 0;
    } else {
        if (period >= _numPeriods) {
            std::stringstream err;
            err << "invalid metrics period, specify [0, " << _numPeriods-1 << "]";
            j["error"] = err.str();
            return j.dump();
        }
        if (period >= _metrics.size()) {
            std::stringstream err;
            err << "this metrics period has not yet accumulated, current range is [0, " << _metrics.size()-1 << "]";
            j["error"] = err.str();
            return j.dump();
        }
    }

    std::string period_str = "1m";

    auto period_length = 0;
    if (period == 0) {
        timeval now_ts;
        gettimeofday(&now_ts, nullptr);
        period_length = now_ts.tv_sec - _metrics[period]->getTS().tv_sec;
    } else {
        period_length = MetricsMgr::PERIOD_SEC;
    }

    j[period_str]["period"]["start_ts"] = _metrics[period]->getTS().tv_sec;
    j[period_str]["period"]["length"] = period_length;

    _metrics[period]->toJSON(j, period_str);

    return j.dump(-1, ' ', true, nlohmann::json::error_handler_t::replace);
}

std::string MetricsMgr::getMetricsMerged(uint64_t period)
{

    nlohmann::json j;

    if (period <= 1 || period > _numPeriods) {
        std::stringstream err;
        err << "invalid metrics period, specify [2, " << _numPeriods << "]";
        j["error"] = err.str();
        return j.dump();
    }

    auto cached = _mergeResultCache.find(period);
    if (cached != _mergeResultCache.end()) {
        // cached results, make sure still valid
        auto t_diff = std::chrono::high_resolution_clock::now() - cached->second.first;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(t_diff).count() < MERGE_CACHE_TTL_MS) {
            return cached->second.second;
        }
        else {
            // expire
            _mergeResultCache.erase(period);
        }
    }

    auto period_length = 0;
    Metrics merged(*this);

    auto p = period;
    for (auto &m : _metrics) {
        if (p-- == 0) {
            break;
        }
        if (m == _metrics.back()) {
            timeval now_ts;
            gettimeofday(&now_ts, nullptr);
            period_length += now_ts.tv_sec - m->getTS().tv_sec;
        } else {
            period_length += MetricsMgr::PERIOD_SEC;
        }
        merged.merge(*m);
    }

    std::stringstream keyBuf;
    keyBuf << period << "m";
    auto period_str = keyBuf.str();

    auto oldest_ts = _metrics.front()->getTS();
    j[period_str]["period"]["start_ts"] = oldest_ts.tv_sec;
    j[period_str]["period"]["length"] = period_length;

    merged.toJSON(j, period_str);

    auto result = j.dump(-1, ' ', true, nlohmann::json::error_handler_t::replace);
    _mergeResultCache[period] = std::pair<std::chrono::high_resolution_clock::time_point, std::string>(std::chrono::high_resolution_clock::now(), result);
    return result;
}

const uint MetricsMgr::PERIOD_SEC;

}