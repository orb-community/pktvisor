#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <Packet.h>
#include <UdpLayer.h>
#include <chrono>
#include <datasketches/datasketches/cpc/cpc_union.hpp>
#include <sstream>

#include <arpa/inet.h>

#include "dns.h"
#include "metrics.h"

namespace pktvisor {

Metrics::Metrics()
{
    gettimeofday(&_bucketTS, nullptr);

    // lock for write
    std::unique_lock lock(_sketchMutex);
    _sketches = std::make_unique<Sketches>();
}

// merge two Metrics objects
void Metrics::merge(Metrics &other)
{

    _numPackets += other._numPackets;
    _numPackets_UDP += other._numPackets_UDP;
    _numPackets_TCP += other._numPackets_TCP;
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

    _sketches->_dnsXactFromTimeMs.merge(other._sketches->_dnsXactFromTimeMs);
    _sketches->_dnsXactToTimeMs.merge(other._sketches->_dnsXactToTimeMs);

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
}

void Metrics::newDNSPacket(pcpp::DnsLayer *dns, Direction dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4)
{

    _DNS_total++;

    if (l3 == pcpp::IPv6) {
        _DNS_IPv6++;
    }

    if (l4 == pcpp::TCP) {
        _DNS_TCP++;
    }

    // lock for write
    std::unique_lock lock(_sketchMutex);

    // only count response codes on responses (not queries)
    if (dns->getDnsHeader()->queryOrResponse == response) {
        _DNS_replies++;
        _sketches->_dns_topRCode.update(dns->getDnsHeader()->responseCode);
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

        // TODO breakout and unit test
        auto first_dot = name.rfind('.');
        if (first_dot != std::string::npos && first_dot > 0) {
            auto second_dot = name.rfind('.', first_dot - 1);
            if (second_dot != std::string::npos) {
                _sketches->_dns_topQname2.update(name.substr(second_dot + 1));
            }
            if (second_dot > 0) {
                auto third_dot = name.rfind('.', second_dot - 1);
                if (third_dot != std::string::npos) {
                    _sketches->_dns_topQname3.update(name.substr(third_dot + 1));
                } else {
                    _sketches->_dns_topQname3.update(name);
                }
            }
        }
    }
}

void Metrics::newDNSXact(pcpp::DnsLayer *dns, Direction dir, hr_clock::duration xact_dur)
{
    // lock for write
    std::unique_lock lock(_sketchMutex);

    _DNS_xacts_total++;
    double xactTime = (double)std::chrono::duration_cast<std::chrono::microseconds>(xact_dur).count() / 1000.0; // milliseconds
    // dir is the direction of the last packet, meaning the reply so from a transaction perspective
    // we look at it from the direction of the query, so the opposite side than we have here
    float to90th = 0.0;
    float from90th = 0.0;
    uint64_t sample_threshold = 10;
    if (dir == toHost) {
        _DNS_xacts_out++;
        _sketches->_dnsXactFromTimeMs.update(xactTime);
        // wait for N samples
        if (_sketches->_dnsXactFromTimeMs.get_n() > sample_threshold) {
            from90th = _sketches->_dnsXactFromTimeMs.get_quantile(0.90);
        }
    } else if (dir == fromHost) {
        _DNS_xacts_in++;
        _sketches->_dnsXactToTimeMs.update(xactTime);
        // wait for N samples
        if (_sketches->_dnsXactToTimeMs.get_n() > sample_threshold) {
            to90th = _sketches->_dnsXactToTimeMs.get_quantile(0.90);
        }
    }

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

void MetricsMgr::newDNSXact(pcpp::DnsLayer *dns, Direction dir, hr_clock::duration xact_dur)
{
    _metrics.back()->newDNSXact(dns, dir, xact_dur);
}

void MetricsMgr::newDNSPacket(pcpp::DnsLayer *dns, Direction dir, pcpp::ProtocolType l3, pcpp::ProtocolType l4)
{
    _metrics.back()->newDNSPacket(dns, dir, l3, l4);
}

void Metrics::newPacket(const pcpp::Packet &packet, pcpp::ProtocolType l3, pcpp::ProtocolType l4, Direction dir)
{

    _numPackets++;

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
        break;
    }

    // lock for write
    std::unique_lock lock(_sketchMutex);

    auto IP4layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    auto IP6layer = packet.getLayerOfType<pcpp::IPv6Layer>();
    if (IP4layer) {
        if (dir == toHost) {
            _sketches->_net_srcIPCard.update(IP4layer->getSrcIpAddress().toInt());
            _sketches->_net_topIPv4.update(IP4layer->getSrcIpAddress().toInt());
        } else if (dir == fromHost) {
            _sketches->_net_dstIPCard.update(IP4layer->getDstIpAddress().toInt());
            _sketches->_net_topIPv4.update(IP4layer->getDstIpAddress().toInt());
        }
    } else if (IP6layer) {
        if (dir == toHost) {
            _sketches->_net_srcIPCard.update((void *)IP6layer->getSrcIpAddress().toIn6Addr(), 16);
            _sketches->_net_topIPv6.update(IP6layer->getSrcIpAddress().toString());
        } else if (dir == fromHost) {
            _sketches->_net_dstIPCard.update((void *)IP6layer->getDstIpAddress().toIn6Addr(), 16);
            _sketches->_net_topIPv6.update(IP6layer->getDstIpAddress().toString());
        }
    }

    auto UDPLayer = packet.getLayerOfType<pcpp::UdpLayer>();
    if (UDPLayer) {
        auto srcPort = ntohs(UDPLayer->getUdpHeader()->portSrc);
        auto dstPort = ntohs(UDPLayer->getUdpHeader()->portDst);
        // track whichever port wasn't a DNS port (in and out)
        if (pcpp::DnsLayer::isDnsPort(dstPort)) {
            _sketches->_dns_topUDPPort.update(srcPort);
        } else if (pcpp::DnsLayer::isDnsPort(srcPort)) {
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
    _metrics.emplace_back(std::make_unique<Metrics>());
    if (_metrics.size() > _numPeriods) {
        // if we're at our period history length, pop the oldest
        _metrics.pop_front();
    }
}

void MetricsMgr::setInitialShiftTS(const pcpp::Packet &packet) {
    _lastShiftTS.tv_sec = packet.getRawPacketReadOnly()->getPacketTimeStamp().tv_sec;
}

void MetricsMgr::newPacket(const pcpp::Packet &packet, QueryResponsePairMgr &pairMgr, pcpp::ProtocolType l4, Direction dir, pcpp::ProtocolType l3)
{
    if (!_singleSummaryMode) {
        // use packet timestamps to track when PERIOD_SEC passes so we don't have to hit system clock
        auto pkt_ts = packet.getRawPacketReadOnly()->getPacketTimeStamp();
        if (pkt_ts.tv_sec - _lastShiftTS.tv_sec > MetricsMgr::PERIOD_SEC) {
            _periodShift();
            _lastShiftTS.tv_sec = packet.getRawPacketReadOnly()->getPacketTimeStamp().tv_sec;
            pairMgr.purgeOldTransactions();
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

    j[key]["packets"]["total"] = _numPackets.load();
    j[key]["packets"]["udp"] = _numPackets_UDP.load();
    j[key]["packets"]["tcp"] = _numPackets_TCP.load();
    j[key]["packets"]["ipv4"] = _numPackets - _numPackets_IPv6;
    j[key]["packets"]["ipv6"] = _numPackets_IPv6.load();
    j[key]["packets"]["in"] = _numPackets_in.load();
    j[key]["packets"]["out"] = _numPackets_out.load();

    j[key]["packets"]["cardinality"]["src_ips_in"] = _sketches->_net_srcIPCard.get_estimate();
    j[key]["packets"]["cardinality"]["dst_ips_out"] = _sketches->_net_dstIPCard.get_estimate();

    //    j[key]["packets"]["rates"]["total"] = _numPackets / period_length;
    //    j[key]["packets"]["rates"]["udp"] = _numPackets_UDP / period_length;
    //    j[key]["packets"]["rates"]["tcp"] = _numPackets_TCP / period_length;
    //    j[key]["packets"]["rates"]["ipv4"] = (_numPackets - _numPackets_IPv6) / period_length;
    //    j[key]["packets"]["rates"]["ipv6"] = _numPackets_IPv6 / period_length;
    //    j[key]["packets"]["rates"]["in"] = _numPackets_in / period_length;
    //    j[key]["packets"]["rates"]["out"] = _numPackets_out / period_length;
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

    j[key]["dns"]["cardinality"]["qname"] = _sketches->_dns_qnameCard.get_estimate();

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

    //    j[key]["dns"]["xact"]["rates"]["in"] = _DNS_xacts_in / period_length;
    //    j[key]["dns"]["xact"]["rates"]["out"] = _DNS_xacts_out / period_length;

    {
        j[key]["dns"]["xact"]["in"]["total"] = _DNS_xacts_in.load();
        j[key]["dns"]["xact"]["in"]["top_slow"] = nlohmann::json::array();
        auto items = _sketches->_dns_slowXactIn.get_frequent_items(datasketches::frequent_items_error_type::NO_FALSE_NEGATIVES);
        for (uint64_t i = 0; i < std::min(10UL, items.size()); i++) {
            j[key]["dns"]["xact"]["in"]["top_slow"][i]["name"] = items[i].get_item();
            j[key]["dns"]["xact"]["in"]["top_slow"][i]["estimate"] = items[i].get_estimate();
        }
    }

    auto d_quantiles = _sketches->_dnsXactFromTimeMs.get_quantiles(fractions, 4);
    if (d_quantiles.size()) {
        j[key]["dns"]["xact"]["out"]["quantiles_ms"]["p50"] = d_quantiles[0];
        j[key]["dns"]["xact"]["out"]["quantiles_ms"]["p90"] = d_quantiles[1];
        j[key]["dns"]["xact"]["out"]["quantiles_ms"]["p95"] = d_quantiles[2];
        j[key]["dns"]["xact"]["out"]["quantiles_ms"]["p99"] = d_quantiles[3];
    }

    d_quantiles = _sketches->_dnsXactToTimeMs.get_quantiles(fractions, 4);
    if (d_quantiles.size()) {
        j[key]["dns"]["xact"]["in"]["quantiles_ms"]["p50"] = d_quantiles[0];
        j[key]["dns"]["xact"]["in"]["quantiles_ms"]["p90"] = d_quantiles[1];
        j[key]["dns"]["xact"]["in"]["quantiles_ms"]["p95"] = d_quantiles[2];
        j[key]["dns"]["xact"]["in"]["quantiles_ms"]["p99"] = d_quantiles[3];
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

    auto period_length = 0;
    Metrics merged;

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

    return j.dump(-1, ' ', true, nlohmann::json::error_handler_t::replace);
}

const uint MetricsMgr::PERIOD_SEC;

}