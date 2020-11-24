package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/ns1/pktvisor/pktvisor_exporter/pktvisor"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	prom_version "github.com/prometheus/common/version"
)

const (
	namespace = "pktvisor"
)

var (
	app_period = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "app_period"),
		"Length of period to capture (s)",
		nil, nil,
	)
	app_uptime_min = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "app_uptime_min"),
		"Uptime (minutes).",
		[]string{"version"}, nil,
	)
	dns_wire_packets_ipv4 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_wire_packets_ipv4"),
		"WirePackets IPv4",
		nil, nil,
	)
	dns_wire_packets_ipv6 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_wire_packets_ipv6"),
		"WirePackets IPv6",
		nil, nil,
	)
	dns_wire_packets_queries = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_wire_packets_queries"),
		"WirePackets Queries",
		nil, nil,
	)
	dns_wire_packets_replies = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_wire_packets_replies"),
		"WirePackets Replies",
		nil, nil,
	)
	dns_wire_packets_tcp = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_wire_packets_tcp"),
		"WirePackets TCP",
		nil, nil,
	)
	dns_wire_packets_total = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_wire_packets_total"),
		"WirePackets Total",
		nil, nil,
	)
	dns_wire_packets_udp = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_wire_packets_udp"),
		"WirePackets UDP",
		nil, nil,
	)
	dns_wire_packets_noerror = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_wire_packets_noerror"),
		"WirePackets NOERROR",
		nil, nil,
	)
	dns_wire_packets_nxdomain = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_wire_packets_nxdomain"),
		"WirePackets NXDOMAIN",
		nil, nil,
	)
	dns_wire_packets_srvfail = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_wire_packets_srvfail"),
		"WirePackets SRVFAIL",
		nil, nil,
	)
	dns_wire_packets_refused = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_wire_packets_refused"),
		"WirePackets REFUSED",
		nil, nil,
	)

	dns_cardinality_qname = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_cardinality_qname"),
		"Cardinality QName",
		nil, nil,
	)

	dns_xact_counts_total = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_xact_counts_total"),
		"Xact Counts Total",
		nil, nil,
	)
	dns_xact_in_quantiles_us_p50 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_xact_in_quantiles_us_p50"),
		"Xact In QuantilesUS P50",
		nil, nil,
	)
	dns_xact_in_quantiles_us_p90 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_xact_in_quantiles_us_p90"),
		"Xact In QuantilesUS P90",
		nil, nil,
	)
	dns_xact_in_quantiles_us_p95 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_xact_in_quantiles_us_p95"),
		"Xact In QuantilesUS P95",
		nil, nil,
	)
	dns_xact_in_quantiles_us_p99 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_xact_in_quantiles_us_p99"),
		"Xact In QuantilesUS P99",
		nil, nil,
	)
	dns_xact_in_top_slow = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_xact_in_top_slow"),
		"Xact In Top Slow",
		[]string{"name"}, nil,
	)
	dns_xact_in_total = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_xact_in_total"),
		"Xact In Total",
		nil, nil,
	)
	dns_xact_out_quantiles_us_p50 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_xact_out_quantiles_us_p50"),
		"Xact Out QuantilesUS P50",
		nil, nil,
	)
	dns_xact_out_quantiles_us_p90 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_xact_out_quantiles_us_p90"),
		"Xact Out QuantilesUS P90",
		nil, nil,
	)
	dns_xact_out_quantiles_us_p95 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_xact_out_quantiles_us_p95"),
		"Xact Out QuantilesUS P95",
		nil, nil,
	)
	dns_xact_out_quantiles_us_p99 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_xact_out_quantiles_us_p99"),
		"Xact Out QuantilesUS P99",
		nil, nil,
	)
	dns_xact_out_top_slow = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_xact_out_top_slow"),
		"Xact Out Top Slow",
		[]string{"name"}, nil,
	)
	dns_xact_out_total = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_xact_out_total"),
		"Xact Out Total",
		nil, nil,
	)

	dns_top_qname2 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_top_qname2"),
		"DNS Top Qname2",
		[]string{"name"}, nil,
	)
	dns_top_qname3 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_top_qname3"),
		"DNS Top Qname3",
		[]string{"name"}, nil,
	)
	dns_top_nxdomain = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_top_nxdomain"),
		"DNS Top NXDomain",
		[]string{"name"}, nil,
	)
	dns_top_qtype = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_top_qtype"),
		"DNS Top QType",
		[]string{"name"}, nil,
	)
	dns_top_rcode = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_top_rcode"),
		"DNS Top Rcode",
		[]string{"name"}, nil,
	)
	dns_top_refused = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_top_refused"),
		"DNS Top Refused",
		[]string{"name"}, nil,
	)
	dns_top_srvfail = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_top_srvfail"),
		"DNS Top SRVFail",
		[]string{"name"}, nil,
	)
	dns_top_udp_ports = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dns_top_udp_ports"),
		"DNS Top UDPPorts",
		[]string{"name"}, nil,
	)

	packets_cardinality_dst_ips_out = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_cardinality_dst_ips_out"),
		"Packets Cardinality DstIpsOut",
		nil, nil,
	)
	packets_cardinality_src_ips_in = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_cardinality_src_ips_in"),
		"Packets Cardinality SrcIpsIn",
		nil, nil,
	)
	packets_ipv4 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_ipv4"),
		"Packets IPv4",
		nil, nil,
	)
	packets_ipv6 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_ipv6"),
		"Packets IPv6",
		nil, nil,
	)
	packets_tcp = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_tcp"),
		"Packets TCP",
		nil, nil,
	)
	packets_total = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_total"),
		"Packets Total",
		nil, nil,
	)
	packets_udp = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_udp"),
		"Packets UDP",
		nil, nil,
	)
	packets_in = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_in"),
		"Packets In",
		nil, nil,
	)
	packets_out = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_out"),
		"Packets Out",
		nil, nil,
	)
	packets_other_l4 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_other_l4"),
		"Packets Other L4",
		nil, nil,
	)
	packets_deep_samples = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_deep_samples"),
		"Packets Deep Samples",
		nil, nil,
	)

	packets_rates_pps_in_p50 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_rates_pps_in_p50"),
		"Packets Rates PPS In P50",
		nil, nil,
	)
	packets_rates_pps_in_p90 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_rates_pps_in_p90"),
		"Packets Rates PPS In P90",
		nil, nil,
	)
	packets_rates_pps_in_p95 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_rates_pps_in_p95"),
		"Packets Rates PPS In P95",
		nil, nil,
	)
	packets_rates_pps_in_p99 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_rates_pps_in_p99"),
		"Packets Rates PPS In P99",
		nil, nil,
	)
	packets_rates_pps_out_p50 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_rates_pps_out_p50"),
		"Packets Rates PPS Out P50",
		nil, nil,
	)
	packets_rates_pps_out_p90 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_rates_pps_out_p90"),
		"Packets Rates PPS Out P90",
		nil, nil,
	)
	packets_rates_pps_out_p95 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_rates_pps_out_p95"),
		"Packets Rates PPS Out P95",
		nil, nil,
	)
	packets_rates_pps_out_p99 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_rates_pps_out_p99"),
		"Packets Rates PPS Out P99",
		nil, nil,
	)

	packets_top_ipv4 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_top_ipv4"),
		"Packets Top IPv4",
		[]string{"name"}, nil,
	)
	packets_top_ipv6 = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_top_ipv6"),
		"Packets Top IPv6",
		[]string{"name"}, nil,
	)
	packets_top_geoloc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_top_geoloc"),
		"Packets Top GeoLoc",
		[]string{"name"}, nil,
	)
	packets_top_asn = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "packets_top_asn"),
		"Packets Top ASN",
		[]string{"name"}, nil,
	)

	period_start_ts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "period_start_ts"),
		"Period Start TS",
		nil, nil,
	)
	period_length = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "period_length"),
		"Period Length",
		nil, nil,
	)
)

// Exporter collects Pktvisor stats from the given server and exports them using
// the prometheus metrics package.
type Exporter struct {
	Client       *pktvisor.Client
	PktvisorHost string
	PktvisorPort string
	Period       int
}

// NewExporter returns an initialized Exporter.
func NewExporter(pktvisorHost string, pktvisorPort string, period int) (*Exporter, error) {
	client := pktvisor.NewClient(time.Duration(10)*time.Second, 5)
	log.Debugln("Init exporter")
	return &Exporter{
		Client:       client,
		PktvisorHost: pktvisorHost,
		PktvisorPort: pktvisorPort,
		Period:       period,
	}, nil
}

// Describe describes all the metrics ever exported by the Pktvisor exporter.
// It implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- app_period
	ch <- app_uptime_min
	ch <- dns_wire_packets_ipv4
	ch <- dns_wire_packets_ipv6
	ch <- dns_wire_packets_queries
	ch <- dns_wire_packets_replies
	ch <- dns_wire_packets_tcp
	ch <- dns_wire_packets_total
	ch <- dns_wire_packets_udp
	ch <- dns_wire_packets_noerror
	ch <- dns_wire_packets_nxdomain
	ch <- dns_wire_packets_srvfail
	ch <- dns_wire_packets_refused
	ch <- dns_cardinality_qname
	ch <- dns_xact_counts_total
	ch <- dns_xact_in_quantiles_us_p50
	ch <- dns_xact_in_quantiles_us_p90
	ch <- dns_xact_in_quantiles_us_p95
	ch <- dns_xact_in_quantiles_us_p99
	ch <- dns_xact_in_top_slow
	ch <- dns_xact_in_total
	ch <- dns_xact_out_quantiles_us_p50
	ch <- dns_xact_out_quantiles_us_p90
	ch <- dns_xact_out_quantiles_us_p95
	ch <- dns_xact_out_quantiles_us_p99
	ch <- dns_xact_out_top_slow
	ch <- dns_xact_out_total
	ch <- dns_top_qname2
	ch <- dns_top_qname3
	ch <- dns_top_nxdomain
	ch <- dns_top_qtype
	ch <- dns_top_rcode
	ch <- dns_top_refused
	ch <- dns_top_srvfail
	ch <- dns_top_udp_ports
	ch <- packets_cardinality_dst_ips_out
	ch <- packets_cardinality_src_ips_in
	ch <- packets_ipv4
	ch <- packets_ipv6
	ch <- packets_tcp
	ch <- packets_total
	ch <- packets_udp
	ch <- packets_in
	ch <- packets_out
	ch <- packets_other_l4
	ch <- packets_deep_samples
	ch <- packets_rates_pps_in_p50
	ch <- packets_rates_pps_in_p90
	ch <- packets_rates_pps_in_p95
	ch <- packets_rates_pps_in_p99
	ch <- packets_rates_pps_out_p50
	ch <- packets_rates_pps_out_p90
	ch <- packets_rates_pps_out_p95
	ch <- packets_rates_pps_out_p99
	ch <- packets_top_ipv4
	ch <- packets_top_ipv6
	ch <- packets_top_geoloc
	ch <- packets_top_asn
	ch <- period_start_ts
	ch <- period_length
}

// Collect fetches the stats from pktvisord service and deliver them as Prometheus Metrics.
// It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	if e.Client == nil {
		log.Errorf("Pktvisor client not configured.")
		return
	}

	appMetrics, err := e.Client.GetAppStats(e.PktvisorHost, e.PktvisorPort)
	if err != nil {
		log.Errorf("Can't get app stats")
		fmt.Println(err)
	}
	ch <- prometheus.MustNewConstMetric(app_period, prometheus.GaugeValue, float64(appMetrics.App.Periods))
	ch <- prometheus.MustNewConstMetric(app_uptime_min, prometheus.GaugeValue, float64(appMetrics.App.UpTimeMin), appMetrics.App.Version)

	windowMetrics, err := e.Client.GetBucketStats(e.PktvisorHost, e.PktvisorPort, e.Period)
	if err != nil {
		log.Errorf("Can't get window stats")
		fmt.Println(err)
	}
	ch <- prometheus.MustNewConstMetric(dns_wire_packets_ipv4, prometheus.GaugeValue, float64(windowMetrics.DNS.WirePackets.Ipv4))
	ch <- prometheus.MustNewConstMetric(dns_wire_packets_ipv6, prometheus.GaugeValue, float64(windowMetrics.DNS.WirePackets.Ipv6))
	ch <- prometheus.MustNewConstMetric(dns_wire_packets_queries, prometheus.GaugeValue, float64(windowMetrics.DNS.WirePackets.Queries))
	ch <- prometheus.MustNewConstMetric(dns_wire_packets_replies, prometheus.GaugeValue, float64(windowMetrics.DNS.WirePackets.Replies))
	ch <- prometheus.MustNewConstMetric(dns_wire_packets_tcp, prometheus.GaugeValue, float64(windowMetrics.DNS.WirePackets.Tcp))
	ch <- prometheus.MustNewConstMetric(dns_wire_packets_total, prometheus.GaugeValue, float64(windowMetrics.DNS.WirePackets.Total))
	ch <- prometheus.MustNewConstMetric(dns_wire_packets_udp, prometheus.GaugeValue, float64(windowMetrics.DNS.WirePackets.Udp))
	ch <- prometheus.MustNewConstMetric(dns_wire_packets_noerror, prometheus.GaugeValue, float64(windowMetrics.DNS.WirePackets.NoError))
	ch <- prometheus.MustNewConstMetric(dns_wire_packets_nxdomain, prometheus.GaugeValue, float64(windowMetrics.DNS.WirePackets.NxDomain))
	ch <- prometheus.MustNewConstMetric(dns_wire_packets_srvfail, prometheus.GaugeValue, float64(windowMetrics.DNS.WirePackets.SrvFail))
	ch <- prometheus.MustNewConstMetric(dns_wire_packets_refused, prometheus.GaugeValue, float64(windowMetrics.DNS.WirePackets.Refused))
	ch <- prometheus.MustNewConstMetric(dns_cardinality_qname, prometheus.GaugeValue, float64(windowMetrics.DNS.Cardinality.Qname))
	ch <- prometheus.MustNewConstMetric(dns_xact_counts_total, prometheus.GaugeValue, float64(windowMetrics.DNS.Xact.Counts.Total))
	ch <- prometheus.MustNewConstMetric(dns_xact_in_quantiles_us_p50, prometheus.GaugeValue, float64(windowMetrics.DNS.Xact.In.QuantilesUS.P50))
	ch <- prometheus.MustNewConstMetric(dns_xact_in_quantiles_us_p90, prometheus.GaugeValue, float64(windowMetrics.DNS.Xact.In.QuantilesUS.P90))
	ch <- prometheus.MustNewConstMetric(dns_xact_in_quantiles_us_p95, prometheus.GaugeValue, float64(windowMetrics.DNS.Xact.In.QuantilesUS.P95))
	ch <- prometheus.MustNewConstMetric(dns_xact_in_quantiles_us_p99, prometheus.GaugeValue, float64(windowMetrics.DNS.Xact.In.QuantilesUS.P99))
	for _, nc := range windowMetrics.DNS.Xact.In.TopSlow {
		ch <- prometheus.MustNewConstMetric(
			dns_xact_in_top_slow,
			prometheus.GaugeValue,
			float64(nc.Estimate),
			nc.Name,
		)
	}
	ch <- prometheus.MustNewConstMetric(dns_xact_in_total, prometheus.GaugeValue, float64(windowMetrics.DNS.Xact.In.Total))
	ch <- prometheus.MustNewConstMetric(dns_xact_out_quantiles_us_p50, prometheus.GaugeValue, float64(windowMetrics.DNS.Xact.Out.QuantilesUS.P50))
	ch <- prometheus.MustNewConstMetric(dns_xact_out_quantiles_us_p90, prometheus.GaugeValue, float64(windowMetrics.DNS.Xact.Out.QuantilesUS.P90))
	ch <- prometheus.MustNewConstMetric(dns_xact_out_quantiles_us_p95, prometheus.GaugeValue, float64(windowMetrics.DNS.Xact.Out.QuantilesUS.P95))
	ch <- prometheus.MustNewConstMetric(dns_xact_out_quantiles_us_p99, prometheus.GaugeValue, float64(windowMetrics.DNS.Xact.Out.QuantilesUS.P99))
	for _, nc := range windowMetrics.DNS.Xact.Out.TopSlow {
		ch <- prometheus.MustNewConstMetric(
			dns_xact_out_top_slow,
			prometheus.GaugeValue,
			float64(nc.Estimate),
			nc.Name,
		)
	}
	ch <- prometheus.MustNewConstMetric(dns_xact_out_total, prometheus.GaugeValue, float64(windowMetrics.DNS.Xact.Out.Total))

	for _, nc := range windowMetrics.DNS.TopQname2 {
		ch <- prometheus.MustNewConstMetric(
			dns_top_qname2,
			prometheus.GaugeValue,
			float64(nc.Estimate),
			nc.Name,
		)
	}
	for _, nc := range windowMetrics.DNS.TopQname3 {
		ch <- prometheus.MustNewConstMetric(
			dns_top_qname3,
			prometheus.GaugeValue,
			float64(nc.Estimate),
			nc.Name,
		)
	}
	for _, nc := range windowMetrics.DNS.TopNX {
		ch <- prometheus.MustNewConstMetric(
			dns_top_nxdomain,
			prometheus.GaugeValue,
			float64(nc.Estimate),
			nc.Name,
		)
	}
	for _, nc := range windowMetrics.DNS.TopQtype {
		ch <- prometheus.MustNewConstMetric(
			dns_top_qtype,
			prometheus.GaugeValue,
			float64(nc.Estimate),
			nc.Name,
		)
	}
	for _, nc := range windowMetrics.DNS.TopRcode {
		ch <- prometheus.MustNewConstMetric(
			dns_top_rcode,
			prometheus.GaugeValue,
			float64(nc.Estimate),
			nc.Name,
		)
	}
	for _, nc := range windowMetrics.DNS.TopREFUSED {
		ch <- prometheus.MustNewConstMetric(
			dns_top_refused,
			prometheus.GaugeValue,
			float64(nc.Estimate),
			nc.Name,
		)
	}
	for _, nc := range windowMetrics.DNS.TopSRVFAIL {
		ch <- prometheus.MustNewConstMetric(
			dns_top_srvfail,
			prometheus.GaugeValue,
			float64(nc.Estimate),
			nc.Name,
		)
	}
	for _, nc := range windowMetrics.DNS.TopUDPPorts {
		ch <- prometheus.MustNewConstMetric(
			dns_top_udp_ports,
			prometheus.GaugeValue,
			float64(nc.Estimate),
			nc.Name,
		)
	}

	ch <- prometheus.MustNewConstMetric(packets_cardinality_dst_ips_out, prometheus.GaugeValue, float64(windowMetrics.Packets.Cardinality.DstIpsOut))
	ch <- prometheus.MustNewConstMetric(packets_cardinality_src_ips_in, prometheus.GaugeValue, float64(windowMetrics.Packets.Cardinality.SrcIpsIn))
	ch <- prometheus.MustNewConstMetric(packets_ipv4, prometheus.GaugeValue, float64(windowMetrics.Packets.Ipv4))
	ch <- prometheus.MustNewConstMetric(packets_ipv6, prometheus.GaugeValue, float64(windowMetrics.Packets.Ipv6))
	ch <- prometheus.MustNewConstMetric(packets_tcp, prometheus.GaugeValue, float64(windowMetrics.Packets.Tcp))
	ch <- prometheus.MustNewConstMetric(packets_total, prometheus.GaugeValue, float64(windowMetrics.Packets.Total))
	ch <- prometheus.MustNewConstMetric(packets_udp, prometheus.GaugeValue, float64(windowMetrics.Packets.Udp))
	ch <- prometheus.MustNewConstMetric(packets_in, prometheus.GaugeValue, float64(windowMetrics.Packets.In))
	ch <- prometheus.MustNewConstMetric(packets_out, prometheus.GaugeValue, float64(windowMetrics.Packets.Out))
	ch <- prometheus.MustNewConstMetric(packets_other_l4, prometheus.GaugeValue, float64(windowMetrics.Packets.OtherL4))
	ch <- prometheus.MustNewConstMetric(packets_deep_samples, prometheus.GaugeValue, float64(windowMetrics.Packets.DeepSamples))
	ch <- prometheus.MustNewConstMetric(packets_rates_pps_in_p50, prometheus.GaugeValue, float64(windowMetrics.Packets.Rates.Pps_in.P50))
	ch <- prometheus.MustNewConstMetric(packets_rates_pps_in_p90, prometheus.GaugeValue, float64(windowMetrics.Packets.Rates.Pps_in.P90))
	ch <- prometheus.MustNewConstMetric(packets_rates_pps_in_p95, prometheus.GaugeValue, float64(windowMetrics.Packets.Rates.Pps_in.P95))
	ch <- prometheus.MustNewConstMetric(packets_rates_pps_in_p99, prometheus.GaugeValue, float64(windowMetrics.Packets.Rates.Pps_in.P99))
	ch <- prometheus.MustNewConstMetric(packets_rates_pps_out_p50, prometheus.GaugeValue, float64(windowMetrics.Packets.Rates.Pps_out.P50))
	ch <- prometheus.MustNewConstMetric(packets_rates_pps_out_p90, prometheus.GaugeValue, float64(windowMetrics.Packets.Rates.Pps_out.P90))
	ch <- prometheus.MustNewConstMetric(packets_rates_pps_out_p95, prometheus.GaugeValue, float64(windowMetrics.Packets.Rates.Pps_out.P95))
	ch <- prometheus.MustNewConstMetric(packets_rates_pps_out_p99, prometheus.GaugeValue, float64(windowMetrics.Packets.Rates.Pps_out.P99))
	ch <- prometheus.MustNewConstMetric(period_start_ts, prometheus.GaugeValue, float64(windowMetrics.Period.StartTS))
	ch <- prometheus.MustNewConstMetric(period_length, prometheus.GaugeValue, float64(windowMetrics.Period.Length))

	for _, nc := range windowMetrics.Packets.TopIpv4 {
		ch <- prometheus.MustNewConstMetric(
			packets_top_ipv4,
			prometheus.GaugeValue,
			float64(nc.Estimate),
			nc.Name,
		)
	}
	for _, nc := range windowMetrics.Packets.TopIpv6 {
		ch <- prometheus.MustNewConstMetric(
			packets_top_ipv6,
			prometheus.GaugeValue,
			float64(nc.Estimate),
			nc.Name,
		)
	}
	for _, nc := range windowMetrics.Packets.TopGeoLoc {
		ch <- prometheus.MustNewConstMetric(
			packets_top_geoloc,
			prometheus.GaugeValue,
			float64(nc.Estimate),
			nc.Name,
		)
	}
	for _, nc := range windowMetrics.Packets.TopASN {
		ch <- prometheus.MustNewConstMetric(
			packets_top_asn,
			prometheus.GaugeValue,
			float64(nc.Estimate),
			nc.Name,
		)
	}
	log.Infof("Pktvisor exporter finished")
}

func init() {
	prometheus.MustRegister(prom_version.NewCollector("pktvisor_exporter"))
}

func main() {
	var (
		listenAddress = flag.String("web.listen-address", ":9998", "Address to listen on for web interface and telemetry.")
		metricsPath   = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
		pktvisorHost  = flag.String("pktvisor.host", "127.0.0.1", "Pktvisor server host")
		pktvisorPort  = flag.String("pktvisor.port", "10853", "Pktvisor server port")
		period        = flag.Int("period", 1, "Bucket period to collect")
	)
	flag.Parse()

	log.Infoln("Starting pktvisor exporter", prom_version.Info())
	log.Infoln("Build context", prom_version.BuildContext())

	exporter, err := NewExporter(*pktvisorHost, *pktvisorPort, *period)
	if err != nil {
		log.Errorf("Can't create exporter : %s", err)
		os.Exit(1)
	}
	log.Infoln("Register exporter")
	prometheus.MustRegister(exporter)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Pktvisor Exporter</title></head>
             <body>
             <h1>Pktvisor Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})

	log.Infoln("Listening on", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
