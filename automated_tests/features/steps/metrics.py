# To use this code, make sure you
#
#     import json
#
# and then, to convert JSON from a string, do
#
#     result = welcome_from_dict(json.loads(json_string))
import threading
from typing import Any, Optional, List, Dict, TypeVar, Type, cast, Callable

T = TypeVar("T")


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
    return x


def to_int(x: Any) -> int:
    assert isinstance(x, int)
    return x


def from_none(x: Any) -> Any:
    assert x is None
    return x


def from_union(fs, x):
    for f in fs:
        try:
            return f(x)
        except:
            pass
    assert False


def from_float(x: Any) -> float:
    assert isinstance(x, (float, int)) and not isinstance(x, bool)
    return float(x)


def to_float(x: Any) -> float:
    assert isinstance(x, float)
    return x


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


def from_dict(f: Callable[[Any], T], x: Any) -> Dict[str, T]:
    assert isinstance(x, dict)
    return {k: f(v) for (k, v) in x.items()}


class Period:
    length: int
    start_ts: int

    def __init__(self, length: int, start_ts: int) -> None:
        self.length = length
        self.start_ts = start_ts

    @staticmethod
    def from_dict(obj: Any) -> 'Period':
        assert isinstance(obj, dict)
        length = from_int(obj.get("length"))
        start_ts = from_int(obj.get("start_ts"))
        return Period(length, start_ts)

    def to_dict(self) -> dict:
        result: dict = {"length": from_int(self.length), "start_ts": from_int(self.start_ts)}
        return result


class PayloadSize:
    live: Optional[int]
    p50: int
    p90: int
    p95: int
    p99: int

    def __init__(self, live: Optional[int], p50: int, p90: int, p95: int, p99: int) -> None:
        self.live = live
        self.p50 = p50
        self.p90 = p90
        self.p95 = p95
        self.p99 = p99

    @staticmethod
    def from_dict(obj: Any) -> 'PayloadSize':
        assert isinstance(obj, dict)
        live = from_union([from_int, from_none], obj.get("live"))
        p50 = from_int(obj.get("p50"))
        p90 = from_int(obj.get("p90"))
        p95 = from_int(obj.get("p95"))
        p99 = from_int(obj.get("p99"))
        return PayloadSize(live, p50, p90, p95, p99)

    def to_dict(self) -> dict:
        result: dict = {"live": from_union([from_int, from_none], self.live), "p50": to_int(self.p50),
                        "p90": to_int(self.p90), "p95": to_int(self.p95), "p99": to_int(self.p99)}
        return result


class Quantiles:
    p50: float
    p90: float
    p95: float
    p99: float

    def __init__(self, p50: float, p90: float, p95: float, p99: float) -> None:
        self.p50 = p50
        self.p90 = p90
        self.p95 = p95
        self.p99 = p99

    @staticmethod
    def from_dict(obj: Any) -> 'Quantiles':
        assert isinstance(obj, dict)
        live = from_union([from_int, from_none], obj.get("live"))
        p50 = from_float(obj.get("p50"))
        p90 = from_float(obj.get("p90"))
        p95 = from_float(obj.get("p95"))
        p99 = from_float(obj.get("p99"))
        return Quantiles(p50, p90, p95, p99)

    def to_dict(self) -> dict:
        result: dict = {"p50": to_float(self.p50), "p90": to_float(self.p90), "p95": to_float(self.p95),
                        "p99": to_float(self.p99)}
        return result


class DHCPRates:
    total: PayloadSize

    def __init__(self, total: PayloadSize) -> None:
        self.total = total

    @staticmethod
    def from_dict(obj: Any) -> 'DHCPRates':
        assert isinstance(obj, dict)
        total = PayloadSize.from_dict(obj.get("total"))
        return DHCPRates(total)

    def to_dict(self) -> dict:
        result: dict = {"total": to_class(PayloadSize, self.total)}
        return result


class WirePackets:
    ack: int
    deep_samples: int
    discover: int
    filtered: int
    offer: int
    request: int
    total: int

    def __init__(self, ack: int, deep_samples: int, discover: int, filtered: int, offer: int, request: int,
                 total: int) -> None:
        self.ack = ack
        self.deep_samples = deep_samples
        self.discover = discover
        self.filtered = filtered
        self.offer = offer
        self.request = request
        self.total = total

    @staticmethod
    def from_dict(obj: Any) -> 'WirePackets':
        assert isinstance(obj, dict)
        ack = from_int(obj.get("ack"))
        deep_samples = from_int(obj.get("deep_samples"))
        discover = from_int(obj.get("discover"))
        filtered = from_int(obj.get("filtered"))
        offer = from_int(obj.get("offer"))
        request = from_int(obj.get("request"))
        total = from_int(obj.get("total"))
        return WirePackets(ack, deep_samples, discover, filtered, offer, request, total)

    def to_dict(self) -> dict:
        result: dict = {"ack": from_int(self.ack), "deep_samples": from_int(self.deep_samples),
                        "discover": from_int(self.discover), "filtered": from_int(self.filtered),
                        "offer": from_int(self.offer), "request": from_int(self.request), "total": from_int(self.total)}
        return result


class DHCP:
    period: Period
    rates: DHCPRates
    wire_packets: WirePackets

    def __init__(self, period: Period, rates: DHCPRates, wire_packets: WirePackets) -> None:
        self.period = period
        self.rates = rates
        self.wire_packets = wire_packets

    @staticmethod
    def from_dict(obj: Any) -> 'DHCP':
        assert isinstance(obj, dict)
        period = Period.from_dict(obj.get("period"))
        rates = DHCPRates.from_dict(obj.get("rates"))
        wire_packets = WirePackets.from_dict(obj.get("wire_packets"))
        return DHCP(period, rates, wire_packets)

    def to_dict(self) -> dict:
        result: dict = {"period": to_class(Period, self.period), "rates": to_class(DHCPRates, self.rates),
                        "wire_packets": to_class(WirePackets, self.wire_packets)}
        return result


class DefaultDHCP:
    dhcp: DHCP

    def __init__(self, dhcp: DHCP) -> None:
        self.dhcp = dhcp

    @staticmethod
    def from_dict(obj: Any) -> 'DefaultDHCP':
        assert isinstance(obj, dict)
        dhcp = DHCP.from_dict(obj.get("dhcp"))
        return DefaultDHCP(dhcp)

    def to_dict(self) -> dict:
        result: dict = {"dhcp": to_class(DHCP, self.dhcp)}
        return result


class DNSCardinality:
    qname: int

    def __init__(self, qname: int) -> None:
        self.qname = qname

    @staticmethod
    def from_dict(obj: Any) -> 'DNSCardinality':
        assert isinstance(obj, dict)
        qname = from_int(obj.get("qname"))
        return DNSCardinality(qname)

    def to_dict(self) -> dict:
        result: dict = {"qname": from_int(self.qname)}
        return result


class Top:
    estimate: int
    name: str

    def __init__(self, estimate: int, name: str) -> None:
        self.estimate = estimate
        self.name = name

    @staticmethod
    def from_dict(obj: Any) -> 'Top':
        assert isinstance(obj, dict)
        estimate = from_int(obj.get("estimate"))
        name = from_str(obj.get("name"))
        return Top(estimate, name)

    def to_dict(self) -> dict:
        result: dict = {"estimate": from_int(self.estimate), "name": from_str(self.name)}
        return result


class Counts:
    timed_out: int
    total: int

    def __init__(self, timed_out: int, total: int) -> None:
        self.timed_out = timed_out
        self.total = total

    @staticmethod
    def from_dict(obj: Any) -> 'Counts':
        assert isinstance(obj, dict)
        timed_out = from_int(obj.get("timed_out"))
        total = from_int(obj.get("total"))
        return Counts(timed_out, total)

    def to_dict(self) -> dict:
        result: dict = {}
        result["timed_out"] = from_int(self.timed_out)
        result["total"] = from_int(self.total)
        return result


class In:
    top_slow: List[Any]
    total: int

    def __init__(self, top_slow: List[Any], total: int) -> None:
        self.top_slow = top_slow
        self.total = total

    @staticmethod
    def from_dict(obj: Any) -> 'In':
        assert isinstance(obj, dict)
        top_slow = from_list(lambda x: x, obj.get("top_slow"))
        total = from_int(obj.get("total"))
        return In(top_slow, total)

    def to_dict(self) -> dict:
        result: dict = {"top_slow": from_list(lambda x: x, self.top_slow), "total": from_int(self.total)}
        return result


class Ratio:
    quantiles: Quantiles

    def __init__(self, quantiles: Quantiles) -> None:
        self.quantiles = quantiles

    @staticmethod
    def from_dict(obj: Any) -> 'Ratio':
        assert isinstance(obj, dict)
        quantiles = Quantiles.from_dict(obj.get("quantiles"))
        return Ratio(quantiles)

    def to_dict(self) -> dict:
        result: dict = {"quantiles": to_class(Quantiles, self.quantiles)}
        return result


class Xact:
    counts: Counts
    xact_in: In
    out: In
    ratio: Ratio

    def __init__(self, counts: Counts, xact_in: In, out: In, ratio: Ratio) -> None:
        self.counts = counts
        self.xact_in = xact_in
        self.out = out
        self.ratio = ratio

    @staticmethod
    def from_dict(obj: Any) -> 'Xact':
        assert isinstance(obj, dict)
        counts = Counts.from_dict(obj.get("counts"))
        xact_in = In.from_dict(obj.get("in"))
        out = In.from_dict(obj.get("out"))
        ratio = Ratio.from_dict(obj.get("ratio"))
        return Xact(counts, xact_in, out, ratio)

    def to_dict(self) -> dict:
        result: dict = {"counts": to_class(Counts, self.counts), "in": to_class(In, self.xact_in),
                        "out": to_class(In, self.out), "ratio": to_class(Ratio, self.ratio)}
        return result


class DNS:
    cardinality: DNSCardinality
    period: Period
    rates: DHCPRates
    top_nodata: List[Any]
    top_nxdomain: List[Any]
    top_qname2: List[Top]
    top_qname3: List[Top]
    top_qname_by_resp_bytes: List[Top]
    top_qtype: List[Top]
    top_rcode: List[Top]
    top_refused: List[Any]
    top_srvfail: List[Any]
    top_udp_ports: List[Top]
    wire_packets: Dict[str, int]
    xact: Xact

    def __init__(self, cardinality: DNSCardinality, period: Period, rates: DHCPRates, top_nodata: List[Any],
                 top_nxdomain: List[Any], top_qname2: List[Top], top_qname3: List[Top],
                 top_qname_by_resp_bytes: List[Top], top_qtype: List[Top], top_rcode: List[Top], top_refused: List[Any],
                 top_srvfail: List[Any], top_udp_ports: List[Top], wire_packets: Dict[str, int], xact: Xact) -> None:
        self.cardinality = cardinality
        self.period = period
        self.rates = rates
        self.top_nodata = top_nodata
        self.top_nxdomain = top_nxdomain
        self.top_qname2 = top_qname2
        self.top_qname3 = top_qname3
        self.top_qname_by_resp_bytes = top_qname_by_resp_bytes
        self.top_qtype = top_qtype
        self.top_rcode = top_rcode
        self.top_refused = top_refused
        self.top_srvfail = top_srvfail
        self.top_udp_ports = top_udp_ports
        self.wire_packets = wire_packets
        self.xact = xact

    @staticmethod
    def from_dict(obj: Any) -> 'DNS':
        assert isinstance(obj, dict)
        cardinality = DNSCardinality.from_dict(obj.get("cardinality"))
        period = Period.from_dict(obj.get("period"))
        rates = DHCPRates.from_dict(obj.get("rates"))
        top_nodata = from_list(lambda x: x, obj.get("top_nodata"))
        top_nxdomain = from_list(lambda x: x, obj.get("top_nxdomain"))
        top_qname2 = from_list(Top.from_dict, obj.get("top_qname2"))
        top_qname3 = from_list(Top.from_dict, obj.get("top_qname3"))
        top_qname_by_resp_bytes = from_list(Top.from_dict, obj.get("top_qname_by_resp_bytes"))
        top_qtype = from_list(Top.from_dict, obj.get("top_qtype"))
        top_rcode = from_list(Top.from_dict, obj.get("top_rcode"))
        top_refused = from_list(lambda x: x, obj.get("top_refused"))
        top_srvfail = from_list(lambda x: x, obj.get("top_srvfail"))
        top_udp_ports = from_list(Top.from_dict, obj.get("top_udp_ports"))
        wire_packets = from_dict(from_int, obj.get("wire_packets"))
        xact = Xact.from_dict(obj.get("xact"))
        return DNS(cardinality, period, rates, top_nodata, top_nxdomain, top_qname2, top_qname3,
                   top_qname_by_resp_bytes, top_qtype, top_rcode, top_refused, top_srvfail, top_udp_ports, wire_packets,
                   xact)

    def to_dict(self) -> dict:
        result: dict = {"cardinality": to_class(DNSCardinality, self.cardinality),
                        "period": to_class(Period, self.period), "rates": to_class(DHCPRates, self.rates),
                        "top_nodata": from_list(lambda x: x, self.top_nodata),
                        "top_nxdomain": from_list(lambda x: x, self.top_nxdomain),
                        "top_qname2": from_list(lambda x: to_class(Top, x), self.top_qname2),
                        "top_qname3": from_list(lambda x: to_class(Top, x), self.top_qname3),
                        "top_qname_by_resp_bytes": from_list(lambda x: to_class(Top, x), self.top_qname_by_resp_bytes),
                        "top_qtype": from_list(lambda x: to_class(Top, x), self.top_qtype),
                        "top_rcode": from_list(lambda x: to_class(Top, x), self.top_rcode),
                        "top_refused": from_list(lambda x: x, self.top_refused),
                        "top_srvfail": from_list(lambda x: x, self.top_srvfail),
                        "top_udp_ports": from_list(lambda x: to_class(Top, x), self.top_udp_ports),
                        "wire_packets": from_dict(from_int, self.wire_packets), "xact": to_class(Xact, self.xact)}
        return result


class DefaultDNS:
    dns: DNS

    def __init__(self, dns: DNS) -> None:
        self.dns = dns

    @staticmethod
    def from_dict(obj: Any) -> 'DefaultDNS':
        assert isinstance(obj, dict)
        dns = DNS.from_dict(obj.get("dns"))
        return DefaultDNS(dns)

    def to_dict(self) -> dict:
        result: dict = {"dns": to_class(DNS, self.dns)}
        return result


class PacketsCardinality:
    dst_ips_out: int
    src_ips_in: int

    def __init__(self, dst_ips_out: int, src_ips_in: int) -> None:
        self.dst_ips_out = dst_ips_out
        self.src_ips_in = src_ips_in

    @staticmethod
    def from_dict(obj: Any) -> 'PacketsCardinality':
        assert isinstance(obj, dict)
        dst_ips_out = from_int(obj.get("dst_ips_out"))
        src_ips_in = from_int(obj.get("src_ips_in"))
        return PacketsCardinality(dst_ips_out, src_ips_in)

    def to_dict(self) -> dict:
        result: dict = {"dst_ips_out": from_int(self.dst_ips_out), "src_ips_in": from_int(self.src_ips_in)}
        return result


class TCP:
    syn: int

    def __init__(self, syn: int) -> None:
        self.syn = syn

    @staticmethod
    def from_dict(obj: Any) -> 'TCP':
        assert isinstance(obj, dict)
        syn = from_int(obj.get("syn"))
        return TCP(syn)

    def to_dict(self) -> dict:
        result: dict = {"syn": from_int(self.syn)}
        return result


class Protocol:
    tcp: TCP

    def __init__(self, tcp: TCP) -> None:
        self.tcp = tcp

    @staticmethod
    def from_dict(obj: Any) -> 'Protocol':
        assert isinstance(obj, dict)
        tcp = TCP.from_dict(obj.get("tcp"))
        return Protocol(tcp)

    def to_dict(self) -> dict:
        result: dict = {"tcp": to_class(TCP, self.tcp)}
        return result


class PacketsRates:
    bytes_in: PayloadSize
    bytes_out: PayloadSize
    pps_in: PayloadSize
    pps_out: PayloadSize
    pps_total: PayloadSize

    def __init__(self, bytes_in: PayloadSize, bytes_out: PayloadSize, pps_in: PayloadSize, pps_out: PayloadSize,
                 pps_total: PayloadSize) -> None:
        self.bytes_in = bytes_in
        self.bytes_out = bytes_out
        self.pps_in = pps_in
        self.pps_out = pps_out
        self.pps_total = pps_total

    @staticmethod
    def from_dict(obj: Any) -> 'PacketsRates':
        assert isinstance(obj, dict)
        bytes_in = PayloadSize.from_dict(obj.get("bytes_in"))
        bytes_out = PayloadSize.from_dict(obj.get("bytes_out"))
        pps_in = PayloadSize.from_dict(obj.get("pps_in"))
        pps_out = PayloadSize.from_dict(obj.get("pps_out"))
        pps_total = PayloadSize.from_dict(obj.get("pps_total"))
        return PacketsRates(bytes_in, bytes_out, pps_in, pps_out, pps_total)

    def to_dict(self) -> dict:
        result: dict = {"bytes_in": to_class(PayloadSize, self.bytes_in),
                        "bytes_out": to_class(PayloadSize, self.bytes_out),
                        "pps_in": to_class(PayloadSize, self.pps_in), "pps_out": to_class(PayloadSize, self.pps_out),
                        "pps_total": to_class(PayloadSize, self.pps_total)}
        return result


class Packets:
    cardinality: PacketsCardinality
    deep_samples: int
    filtered: int
    packets_in: int
    ipv4: int
    ipv6: int
    other_l4: int
    out: int
    payload_size: PayloadSize
    period: Period
    protocol: Protocol
    rates: PacketsRates
    tcp: int
    top_asn: List[Any]
    top_geo_loc: List[Any]
    top_ipv4: List[Any]
    top_ipv6: List[Top]
    total: int
    udp: int

    def __init__(self, cardinality: PacketsCardinality, deep_samples: int, filtered: int, packets_in: int, ipv4: int,
                 ipv6: int, other_l4: int, out: int, payload_size: PayloadSize, period: Period, protocol: Protocol,
                 rates: PacketsRates, tcp: int, top_asn: List[Any], top_geo_loc: List[Any], top_ipv4: List[Any],
                 top_ipv6: List[Top], total: int, udp: int) -> None:
        self.cardinality = cardinality
        self.deep_samples = deep_samples
        self.filtered = filtered
        self.packets_in = packets_in
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.other_l4 = other_l4
        self.out = out
        self.payload_size = payload_size
        self.period = period
        self.protocol = protocol
        self.rates = rates
        self.tcp = tcp
        self.top_asn = top_asn
        self.top_geo_loc = top_geo_loc
        self.top_ipv4 = top_ipv4
        self.top_ipv6 = top_ipv6
        self.total = total
        self.udp = udp

    @staticmethod
    def from_dict(obj: Any) -> 'Packets':
        assert isinstance(obj, dict)
        cardinality = PacketsCardinality.from_dict(obj.get("cardinality"))
        deep_samples = from_int(obj.get("deep_samples"))
        filtered = from_int(obj.get("filtered"))
        packets_in = from_int(obj.get("in"))
        ipv4 = from_int(obj.get("ipv4"))
        ipv6 = from_int(obj.get("ipv6"))
        other_l4 = from_int(obj.get("other_l4"))
        out = from_int(obj.get("out"))
        payload_size = PayloadSize.from_dict(obj.get("payload_size"))
        period = Period.from_dict(obj.get("period"))
        protocol = Protocol.from_dict(obj.get("protocol"))
        rates = PacketsRates.from_dict(obj.get("rates"))
        tcp = from_int(obj.get("tcp"))
        top_asn = from_list(lambda x: x, obj.get("top_ASN"))
        top_geo_loc = from_list(lambda x: x, obj.get("top_geoLoc"))
        top_ipv4 = from_list(lambda x: x, obj.get("top_ipv4"))
        top_ipv6 = from_list(Top.from_dict, obj.get("top_ipv6"))
        total = from_int(obj.get("total"))
        udp = from_int(obj.get("udp"))
        return Packets(cardinality, deep_samples, filtered, packets_in, ipv4, ipv6, other_l4, out, payload_size, period,
                       protocol, rates, tcp, top_asn, top_geo_loc, top_ipv4, top_ipv6, total, udp)

    def to_dict(self) -> dict:
        result: dict = {"cardinality": to_class(PacketsCardinality, self.cardinality),
                        "deep_samples": from_int(self.deep_samples), "filtered": from_int(self.filtered),
                        "in": from_int(self.packets_in), "ipv4": from_int(self.ipv4), "ipv6": from_int(self.ipv6),
                        "other_l4": from_int(self.other_l4), "out": from_int(self.out),
                        "payload_size": to_class(PayloadSize, self.payload_size),
                        "period": to_class(Period, self.period), "protocol": to_class(Protocol, self.protocol),
                        "rates": to_class(PacketsRates, self.rates), "tcp": from_int(self.tcp),
                        "top_ASN": from_list(lambda x: x, self.top_asn),
                        "top_geoLoc": from_list(lambda x: x, self.top_geo_loc),
                        "top_ipv4": from_list(lambda x: x, self.top_ipv4),
                        "top_ipv6": from_list(lambda x: to_class(Top, x), self.top_ipv6), "total": from_int(self.total),
                        "udp": from_int(self.udp)}
        return result


class DefaultNet:
    packets: Packets

    def __init__(self, packets: Packets) -> None:
        self.packets = packets

    @staticmethod
    def from_dict(obj: Any) -> 'DefaultNet':
        assert isinstance(obj, dict)
        packets = Packets.from_dict(obj.get("packets"))
        return DefaultNet(packets)

    def to_dict(self) -> dict:
        result: dict = {"packets": to_class(Packets, self.packets)}
        return result


class Pcap:
    if_drops: int
    os_drops: int
    period: Period
    tcp_reassembly_errors: int

    def __init__(self, if_drops: int, os_drops: int, period: Period, tcp_reassembly_errors: int) -> None:
        self.if_drops = if_drops
        self.os_drops = os_drops
        self.period = period
        self.tcp_reassembly_errors = tcp_reassembly_errors

    @staticmethod
    def from_dict(obj: Any) -> 'Pcap':
        assert isinstance(obj, dict)
        if_drops = from_int(obj.get("if_drops"))
        os_drops = from_int(obj.get("os_drops"))
        period = Period.from_dict(obj.get("period"))
        tcp_reassembly_errors = from_int(obj.get("tcp_reassembly_errors"))
        return Pcap(if_drops, os_drops, period, tcp_reassembly_errors)

    def to_dict(self) -> dict:
        result: dict = {"if_drops": from_int(self.if_drops), "os_drops": from_int(self.os_drops),
                        "period": to_class(Period, self.period),
                        "tcp_reassembly_errors": from_int(self.tcp_reassembly_errors)}
        return result


class DefaultPcapStats:
    pcap: Pcap

    def __init__(self, pcap: Pcap) -> None:
        self.pcap = pcap

    @staticmethod
    def from_dict(obj: Any) -> 'DefaultPcapStats':
        assert isinstance(obj, dict)
        pcap = Pcap.from_dict(obj.get("pcap"))
        return DefaultPcapStats(pcap)

    def to_dict(self) -> dict:
        result: dict = {"pcap": to_class(Pcap, self.pcap)}
        return result


class Default:
    default_dhcp: DefaultDHCP
    default_dns: DefaultDNS
    default_net: DefaultNet
    default_pcap_stats: DefaultPcapStats

    def __init__(self, default_dhcp: DefaultDHCP, default_dns: DefaultDNS, default_net: DefaultNet,
                 default_pcap_stats: DefaultPcapStats) -> None:
        self.default_dhcp = default_dhcp
        self.default_dns = default_dns
        self.default_net = default_net
        self.default_pcap_stats = default_pcap_stats

    @staticmethod
    def from_dict(obj: Any) -> 'Default':
        assert isinstance(obj, dict)
        default_dhcp = DefaultDHCP.from_dict(obj.get("default-default-dhcp"))
        default_dns = DefaultDNS.from_dict(obj.get("default-default-dns"))
        default_net = DefaultNet.from_dict(obj.get("default-default-net"))
        default_pcap_stats = DefaultPcapStats.from_dict(obj.get("default-default-pcap_stats"))
        return Default(default_dhcp, default_dns, default_net, default_pcap_stats)

    def to_dict(self) -> dict:
        result: dict = {"default-default-dhcp": to_class(DefaultDHCP, self.default_dhcp),
                        "default-default-dns": to_class(DefaultDNS, self.default_dns),
                        "default-default-net": to_class(DefaultNet, self.default_net),
                        "default-default-pcap_stats": to_class(DefaultPcapStats, self.default_pcap_stats)}
        return result


class InputResources:
    cpu_usage: PayloadSize
    deep_samples: int
    event_rate: PayloadSize
    handler_count: int
    memory_bytes: PayloadSize
    period: Period
    policy_count: int
    total: int

    def __init__(self, cpu_usage: PayloadSize, deep_samples: int, event_rate: PayloadSize, handler_count: int,
                 memory_bytes: PayloadSize, period: Period, policy_count: int, total: int) -> None:
        self.cpu_usage = cpu_usage
        self.deep_samples = deep_samples
        self.event_rate = event_rate
        self.handler_count = handler_count
        self.memory_bytes = memory_bytes
        self.period = period
        self.policy_count = policy_count
        self.total = total

    @staticmethod
    def from_dict(obj: Any) -> 'InputResources':
        assert isinstance(obj, dict)
        cpu_usage = PayloadSize.from_dict(obj.get("cpu_usage"))
        deep_samples = from_int(obj.get("deep_samples"))
        event_rate = PayloadSize.from_dict(obj.get("event_rate"))
        handler_count = from_int(obj.get("handler_count"))
        memory_bytes = PayloadSize.from_dict(obj.get("memory_bytes"))
        period = Period.from_dict(obj.get("period"))
        policy_count = from_int(obj.get("policy_count"))
        total = from_int(obj.get("total"))
        return InputResources(cpu_usage, deep_samples, event_rate, handler_count, memory_bytes, period, policy_count,
                              total)

    def to_dict(self) -> dict:
        result: dict = {"cpu_usage": to_class(PayloadSize, self.cpu_usage), "deep_samples": from_int(self.deep_samples),
                        "event_rate": to_class(PayloadSize, self.event_rate),
                        "handler_count": from_int(self.handler_count),
                        "memory_bytes": to_class(PayloadSize, self.memory_bytes),
                        "period": to_class(Period, self.period), "policy_count": from_int(self.policy_count),
                        "total": from_int(self.total)}
        return result


class DefaultResourcesDefaultResources:
    input_resources: InputResources

    def __init__(self, input_resources: InputResources) -> None:
        self.input_resources = input_resources

    @staticmethod
    def from_dict(obj: Any) -> 'DefaultResourcesDefaultResources':
        assert isinstance(obj, dict)
        input_resources = InputResources.from_dict(obj.get("input_resources"))
        return DefaultResourcesDefaultResources(input_resources)

    def to_dict(self) -> dict:
        result: dict = {"input_resources": to_class(InputResources, self.input_resources)}
        return result


class WelcomeDefaultResources:
    default_resources: DefaultResourcesDefaultResources

    def __init__(self,
                 default_resources: DefaultResourcesDefaultResources) -> None:
        self.default_resources = default_resources

    @staticmethod
    def from_dict(obj: Any) -> 'WelcomeDefaultResources':
        assert isinstance(obj, dict)
        default_resources = DefaultResourcesDefaultResources.from_dict(
            obj.get("default-995f1f110d78e4ee-resources"))
        return WelcomeDefaultResources(default_resources)

    def to_dict(self) -> dict:
        result: dict = {"default-995f1f110d78e4ee-resources": to_class(
            DefaultResourcesDefaultResources,
            self.default_resources)}
        return result


class WelcomeDefault:
    default: Default

    def __init__(self, default: Default) -> None:
        self.default = default

    @staticmethod
    def from_dict(obj: Any) -> 'WelcomeDefault':
        assert isinstance(obj, dict)
        default = Default.from_dict(obj.get("default"))
        return WelcomeDefault(default)

    def to_dict(self) -> dict:
        result: dict = {"default": to_class(Default, self.default)}
        return result


def welcome_default_from_dict(s: Any) -> WelcomeDefault:
    return WelcomeDefault.from_dict(s)


def welcome_default_to_dict(x: WelcomeDefault) -> Any:
    return to_class(WelcomeDefault, x)
