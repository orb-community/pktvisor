/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

package client

// NameCount represents the count of a unique domain name
type NameCount struct {
	Name     string `json:"name"`
	Estimate int64  `json:"estimate"`
}

// DNSPayload contains the information specifically for the DNS protocol
type DNSPayload struct {
	WirePackets struct {
		Ipv4     int64 `json:"ipv4"`
		Ipv6     int64 `json:"ipv6"`
		Queries  int64 `json:"queries"`
		Replies  int64 `json:"replies"`
		TCP      int64 `json:"tcp"`
		Total    int64 `json:"total"`
		UDP      int64 `json:"udp"`
		NoError  int64 `json:"noerror"`
		NxDomain int64 `json:"nxdomain"`
		SrvFail  int64 `json:"srvfail"`
		Refused  int64 `json:"refused"`
		Rates    struct {
			Total struct {
				Live int64 `json:"live"`
				P50  int64 `json:"p50"`
				P90  int64 `json:"p90"`
				P95  int64 `json:"p95"`
				P99  int64 `json:"p99"`
			} `json:"total"`
		} `json:"rates"`
	} `json:"wire_packets"`
	Cardinality struct {
		Qname int64 `json:"qname"`
	} `json:"cardinality"`
	Xact struct {
		Counts struct {
			Total int64 `json:"total"`
			TimedOut int64 `json:"timed_out"`
		} `json:"counts"`
		In struct {
			QuantilesUS struct {
				P50 int64 `json:"p50"`
				P90 int64 `json:"p90"`
				P95 int64 `json:"p95"`
				P99 int64 `json:"p99"`
			} `json:"quantiles_us"`
			TopSlow []NameCount `json:"top_slow"`
			Total   int64       `json:"total"`
		} `json:"in"`
		Out struct {
			QuantilesUS struct {
				P50 int64 `json:"p50"`
				P90 int64 `json:"p90"`
				P95 int64 `json:"p95"`
				P99 int64 `json:"p99"`
			} `json:"quantiles_us"`
			TopSlow []NameCount `json:"top_slow"`
			Total   int64       `json:"total"`
		} `json:"out"`
	} `json:"xact"`
	TopQname2   []NameCount `json:"top_qname2"`
	TopQname3   []NameCount `json:"top_qname3"`
	TopNX       []NameCount `json:"top_nxdomain"`
	TopQtype    []NameCount `json:"top_qtype"`
	TopRcode    []NameCount `json:"top_rcode"`
	TopREFUSED  []NameCount `json:"top_refused"`
	TopSRVFAIL  []NameCount `json:"top_srvfail"`
	TopUDPPorts []NameCount `json:"top_udp_ports"`
	Period  PeriodPayload `json:"period"`
}

// PacketPayload contains information about raw packets regardless of protocol
type PacketPayload struct {
	Cardinality struct {
		DstIpsOut int64 `json:"dst_ips_out"`
		SrcIpsIn  int64 `json:"src_ips_in"`
	} `json:"cardinality"`
	Ipv4        int64 `json:"ipv4"`
	Ipv6        int64 `json:"ipv6"`
	TCP         int64 `json:"tcp"`
	Total       int64 `json:"total"`
	UDP         int64 `json:"udp"`
	In          int64 `json:"in"`
	Out         int64 `json:"out"`
	OtherL4     int64 `json:"other_l4"`
	DeepSamples int64 `json:"deep_samples"`
	Rates       struct {
		Pps_in struct {
			Live int64 `json:"live"`
			P50  int64 `json:"p50"`
			P90  int64 `json:"p90"`
			P95  int64 `json:"p95"`
			P99  int64 `json:"p99"`
		} `json:"pps_in"`
		Pps_out struct {
			Live int64 `json:"live"`
			P50  int64 `json:"p50"`
			P90  int64 `json:"p90"`
			P95  int64 `json:"p95"`
			P99  int64 `json:"p99"`
		} `json:"pps_out"`
		Pps_total struct {
			Live int64 `json:"live"`
			P50  int64 `json:"p50"`
			P90  int64 `json:"p90"`
			P95  int64 `json:"p95"`
			P99  int64 `json:"p99"`
		} `json:"pps_total"`
	} `json:"rates"`
	TopIpv4   []NameCount `json:"top_ipv4"`
	TopIpv6   []NameCount `json:"top_ipv6"`
	TopGeoLoc []NameCount `json:"top_geoLoc"`
	TopASN    []NameCount `json:"top_asn"`
	Period  PeriodPayload `json:"period"`
}

// PeriodPayload indicates the period of time for which a snapshot refers to
type PeriodPayload struct {
	StartTS int64 `json:"start_ts"`
	Length  int64 `json:"length"`
}

// StatSnapshot is a snapshot of a given period from pktvisord
type StatSnapshot struct {
	DNS     DNSPayload    `json:"dns"`
	Packets PacketPayload `json:"packets"`
}
