/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

package ui

import (
	"fmt"
	"github.com/jroimartin/gocui"
	"pktvisor/pkg/client"
	"time"
)

func (u *ui) updateHeader(v *gocui.View, window5m *client.StatSnapshot) {
	v.Clear()
	pcounts := window5m.Packets
	// there may be some unknown
	inOutDiff := pcounts.Total - (pcounts.In + pcounts.Out)
	_, _ = fmt.Fprintf(v, "Pkts  %d | UDP %d (%3.1f%%) | TCP %d (%3.1f%%) | Other %d (%3.1f%%) | IPv4 %d (%3.1f%%) | IPv6 %d (%3.1f%%) | In %d (%3.1f%%) | Out %d (%3.1f%%) | Deep Samples %d (%3.1f%%)\n",
		pcounts.Total,
		pcounts.UDP,
		(float64(pcounts.UDP)/float64(pcounts.Total))*100,
		pcounts.TCP,
		(float64(pcounts.TCP)/float64(pcounts.Total))*100,
		pcounts.OtherL4,
		(float64(pcounts.OtherL4)/float64(pcounts.Total))*100,
		pcounts.Ipv4,
		(float64(pcounts.Ipv4)/float64(pcounts.Total))*100,
		pcounts.Ipv6,
		(float64(pcounts.Ipv6)/float64(pcounts.Total))*100,
		pcounts.In,
		(float64(pcounts.In)/float64(pcounts.Total-inOutDiff))*100,
		pcounts.Out,
		(float64(pcounts.Out)/float64(pcounts.Total-inOutDiff))*100,
		pcounts.DeepSamples,
		(float64(pcounts.DeepSamples)/float64(pcounts.Total))*100,
	)
	_, _ = fmt.Fprintf(v, "Pkt Rates Total %d/s %d/%d/%d/%d pps | In %d/s %d/%d/%d/%d pps | Out %d/s %d/%d/%d/%d pps | IP Card. In: %d | Out: %d | TCP Errors %d | OS Drops %d | IF Drops %d\n\n",
		pcounts.Rates.Pps_total.Live,
		pcounts.Rates.Pps_total.P50,
		pcounts.Rates.Pps_total.P90,
		pcounts.Rates.Pps_total.P95,
		pcounts.Rates.Pps_total.P99,
		pcounts.Rates.Pps_in.Live,
		pcounts.Rates.Pps_in.P50,
		pcounts.Rates.Pps_in.P90,
		pcounts.Rates.Pps_in.P95,
		pcounts.Rates.Pps_in.P99,
		pcounts.Rates.Pps_out.Live,
		pcounts.Rates.Pps_out.P50,
		pcounts.Rates.Pps_out.P90,
		pcounts.Rates.Pps_out.P95,
		pcounts.Rates.Pps_out.P99,
		pcounts.Cardinality.SrcIpsIn,
		pcounts.Cardinality.DstIpsOut,
		window5m.Pcap.TcpReassemblyErrors,
		window5m.Pcap.OsDrops,
		window5m.Pcap.IfDrops,
	)
	dnsc := window5m.DNS.WirePackets
	_, _ = fmt.Fprintf(v, "DNS Wire Pkts %d/%d | Rates Total %d/s %d/%d/%d/%d | UDP %d (%3.1f%%) | TCP %d (%3.1f%%) | IPv4 %d (%3.1f%%) | IPv6 %d (%3.1f%%) | Query %d (%3.1f%%) | Response %d (%3.1f%%)\n",
		dnsc.Total-dnsc.Filtered,
		dnsc.Total,
		window5m.DNS.Rates.Total.Live,
		window5m.DNS.Rates.Total.P50,
		window5m.DNS.Rates.Total.P90,
		window5m.DNS.Rates.Total.P95,
		window5m.DNS.Rates.Total.P99,
		dnsc.UDP,
		(float64(dnsc.UDP)/float64(dnsc.Total))*100,
		dnsc.TCP,
		(float64(dnsc.TCP)/float64(dnsc.Total))*100,
		dnsc.Ipv4,
		(float64(dnsc.Ipv4)/float64(dnsc.Total))*100,
		dnsc.Ipv6,
		(float64(dnsc.Ipv6)/float64(dnsc.Total))*100,
		dnsc.Queries,
		(float64(dnsc.Queries)/float64(dnsc.Total))*100,
		dnsc.Replies,
		(float64(dnsc.Replies)/float64(dnsc.Total))*100,
	)
	xact := window5m.DNS.Xact
	_, _ = fmt.Fprintf(v, "DNS Xacts %d | Timed Out %d | In %d (%3.1f%%) | Out %d (%3.1f%%) | In %3.1f/%3.1f/%3.1f/%3.1f ms | Out %3.1f/%3.1f/%3.1f/%3.1f ms | Qname Card. %d\n",
		xact.Counts.Total,
		xact.Counts.TimedOut,
		xact.In.Total,
		(float64(xact.In.Total)/float64(xact.Counts.Total))*100,
		xact.Out.Total,
		(float64(xact.Out.Total)/float64(xact.Counts.Total))*100,
		float64(xact.In.QuantilesUS.P50)/1000,
		float64(xact.In.QuantilesUS.P90)/1000,
		float64(xact.In.QuantilesUS.P95)/1000,
		float64(xact.In.QuantilesUS.P99)/1000,
		float64(xact.Out.QuantilesUS.P50)/1000,
		float64(xact.Out.QuantilesUS.P90)/1000,
		float64(xact.Out.QuantilesUS.P95)/1000,
		float64(xact.Out.QuantilesUS.P99)/1000,
		window5m.DNS.Cardinality.Qname,
	)
	startTime := time.Unix(window5m.Packets.Period.StartTS, 0)
	endTime := time.Unix(window5m.Packets.Period.StartTS+window5m.Packets.Period.Length, 0)
	_, _ = fmt.Fprintf(v, "DNS NOERROR %d (%3.1f%%) | SRVFAIL %d (%3.1f%%) | NXDOMAIN %d (%3.1f%%) | REFUSED %d (%3.1f%%) | Time Window %v to %v, Period %ds\n",
		dnsc.NoError,
		(float64(dnsc.NoError)/float64(dnsc.Replies))*100,
		dnsc.SrvFail,
		(float64(dnsc.SrvFail)/float64(dnsc.Replies))*100,
		dnsc.NxDomain,
		(float64(dnsc.NxDomain)/float64(dnsc.Replies))*100,
		dnsc.Refused,
		(float64(dnsc.Refused)/float64(dnsc.Replies))*100,
		startTime.Format(time.Kitchen),
		endTime.Format(time.Kitchen),
		window5m.Packets.Period.Length,
	)

}
