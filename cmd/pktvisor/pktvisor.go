package main

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"strconv"

	"net/http"
	//"sort"
	"time"

	"github.com/jroimartin/gocui"
)

var (
	done          = make(chan struct{})
	statHost      = "localhost"
	statPort      = 10853
	refreshPeriod = 1 // seconds
	currentView   = "main"
)

// These two types generalize the one above

type NameCount struct {
	Name     string `json:"name"`
	Estimate int64  `json:"estimate"`
}

type InstantRates struct {
	Packets struct {
		//Ipv4  int64 `json:"ipv4"`
		//Ipv6  int64 `json:"ipv6"`
		//Tcp   int64 `json:"tcp"`
		//Total int64 `json:"total"`
		//Udp   int64 `json:"udp"`
		In  int64 `json:"in"`
		Out int64 `json:"out"`
	} `json:"packets"`
	//DNS struct {
	//InstantRates struct {
	//	In  int64 `json:"in"`
	//	Out int64 `json:"out"`
	//} `json:"rates"`
	//}
}

type StatSnapshot struct {
	DNS struct {
		WirePackets struct {
			Ipv4     int64 `json:"ipv4"`
			Ipv6     int64 `json:"ipv6"`
			Queries  int64 `json:"queries"`
			Replies  int64 `json:"replies"`
			Tcp      int64 `json:"tcp"`
			Total    int64 `json:"total"`
			Udp      int64 `json:"udp"`
			NoError  int64 `json:"noerror"`
			NxDomain int64 `json:"nxdomain"`
			SrvFail  int64 `json:"srvfail"`
			Refused  int64 `json:"refused"`
		} `json:"wire_packets"`
		Cardinality struct {
			Qname int64 `json:"qname"`
		} `json:"cardinality"`
		Xact struct {
			Counts struct {
				Total int64 `json:"total"`
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
	} `json:"dns"`
	Packets struct {
		Cardinality struct {
			DstIpsOut int64 `json:"dst_ips_out"`
			SrcIpsIn  int64 `json:"src_ips_in"`
		} `json:"cardinality"`
		Ipv4        int64 `json:"ipv4"`
		Ipv6        int64 `json:"ipv6"`
		Tcp         int64 `json:"tcp"`
		Total       int64 `json:"total"`
		Udp         int64 `json:"udp"`
		In          int64 `json:"in"`
		Out         int64 `json:"out"`
		OtherL4     int64 `json:"other_l4"`
		DeepSamples int64 `json:"deep_samples"`
		Rates       struct {
			Pps_in struct {
				P50 int64 `json:"p50"`
				P90 int64 `json:"p90"`
				P95 int64 `json:"p95"`
				P99 int64 `json:"p99"`
			} `json:"pps_in"`
			Pps_out struct {
				P50 int64 `json:"p50"`
				P90 int64 `json:"p90"`
				P95 int64 `json:"p95"`
				P99 int64 `json:"p99"`
			} `json:"pps_out"`
		} `json:"rates"`
		TopIpv4   []NameCount `json:"top_ipv4"`
		TopIpv6   []NameCount `json:"top_ipv6"`
		TopGeoLoc []NameCount `json:"top_geoLoc"`
		TopASN    []NameCount `json:"top_asn"`
	} `json:"packets"`
	Period struct {
		StartTS int64 `json:"start_ts"`
		Length  int64 `json:"length"`
	} `json:"period"`
}

func main() {
	// TODO get port from command line
	// statPort =
	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		log.Panicln(err)
	}
	defer g.Close()

	g.SetManagerFunc(layout)

	if err := keybindings(g); err != nil {
		log.Panicln(err)
	}

	go counter(g)

	if err := g.MainLoop(); err != nil && err != gocui.ErrQuit {
		maxX, maxY := g.Size()
		log.Panicf("%s, terminal max size: %d, %d\n", err, maxX, maxY)
	}
}

func updateHeader(v *gocui.View, rates *InstantRates, stats *StatSnapshot) {
	v.Clear()
	pcounts := stats.Packets
	// there may be some unknown
	inOutDiff := pcounts.Total - (pcounts.In + pcounts.Out)
	_, _ = fmt.Fprintf(v, "Pkts  %d | UDP %d (%3.1f%%) | TCP %d (%3.1f%%) | Other %d (%3.1f%%) | IPv4 %d (%3.1f%%) | IPv6 %d (%3.1f%%) | In %d (%3.1f%%) | Out %d (%3.1f%%) | Deep Samples %d (%3.1f%%)\n",
		pcounts.Total,
		pcounts.Udp,
		(float64(pcounts.Udp)/float64(pcounts.Total))*100,
		pcounts.Tcp,
		(float64(pcounts.Tcp)/float64(pcounts.Total))*100,
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
	_, _ = fmt.Fprintf(v, "Pkt Rates In %d/s %d/%d/%d/%d pps | Out %d/s %d/%d/%d/%d pps | IP Card. In: %d | Out: %d\n\n",
		rates.Packets.In,
		pcounts.Rates.Pps_in.P50,
		pcounts.Rates.Pps_in.P90,
		pcounts.Rates.Pps_in.P95,
		pcounts.Rates.Pps_in.P99,
		rates.Packets.Out,
		pcounts.Rates.Pps_out.P50,
		pcounts.Rates.Pps_out.P90,
		pcounts.Rates.Pps_out.P95,
		pcounts.Rates.Pps_out.P99,
		pcounts.Cardinality.SrcIpsIn,
		pcounts.Cardinality.DstIpsOut,
	)
	dnsc := stats.DNS.WirePackets
	_, _ = fmt.Fprintf(v, "DNS Wire Pkts %d (%3.1f%%) | UDP %d (%3.1f%%) | TCP %d (%3.1f%%) | IPv4 %d (%3.1f%%) | IPv6 %d (%3.1f%%) | Query %d (%3.1f%%) | Response %d (%3.1f%%)\n",
		dnsc.Total,
		(float64(dnsc.Total)/float64(pcounts.Total))*100,
		dnsc.Udp,
		(float64(dnsc.Udp)/float64(dnsc.Total))*100,
		dnsc.Tcp,
		(float64(dnsc.Tcp)/float64(dnsc.Total))*100,
		dnsc.Ipv4,
		(float64(dnsc.Ipv4)/float64(dnsc.Total))*100,
		dnsc.Ipv6,
		(float64(dnsc.Ipv6)/float64(dnsc.Total))*100,
		dnsc.Queries,
		(float64(dnsc.Queries)/float64(dnsc.Total))*100,
		dnsc.Replies,
		(float64(dnsc.Replies)/float64(dnsc.Total))*100,
	)
	xact := stats.DNS.Xact
	_, _ = fmt.Fprintf(v, "DNS Xacts %d | In %d (%3.1f%%) | Out %d (%3.1f%%) | In %3.1f/%3.1f/%3.1f/%3.1f ms | Out %3.1f/%3.1f/%3.1f/%3.1f ms | Qname Card. %d\n",
		xact.Counts.Total,
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
		stats.DNS.Cardinality.Qname,
	)
	startTime := time.Unix(stats.Period.StartTS, 0)
	endTime := time.Unix(stats.Period.StartTS+stats.Period.Length, 0)
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
		stats.Period.Length,
	)

}

func updateTable(data []NameCount, v *gocui.View, baseNumber int64) {
	v.Clear()
	top3 := 0
	for _, stat := range data {
		w, _ := v.Size()
		numStr := ""
		if baseNumber > 0 && top3 < 3 {
			numStr = fmt.Sprintf("%d (%4.1f%%)", stat.Estimate, float64(stat.Estimate)/float64(baseNumber)*100)
		} else {
			numStr = fmt.Sprintf("%d", stat.Estimate)
		}
		fmt.Fprintf(v, "%-" + strconv.Itoa(w - len(numStr) - 1) + "s %s\n", stat.Name, numStr)
		top3++
	}
}

func doMainView(g *gocui.Gui) error {

	maxX, _ := g.Size()

	//viewsWidth := 15
	viewsHeight := 7
	tableHeight := 8
	tableWidth := (maxX / 4) - 1
	row1Y := viewsHeight + 1
	row2Y := row1Y + tableHeight + 1
	row3Y := row2Y + tableHeight + 1
	row4Y := row3Y + tableHeight + 1
	midCol1 := 0
	midCol2 := midCol1 + tableWidth + 1
	midCol3 := midCol2 + tableWidth + 1

	// row 3

	if v, err := g.SetView("top_ipv4", midCol2, row3Y, midCol2+tableWidth, row3Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "IPv4"
	}

	if v, err := g.SetView("top_ipv6", midCol3, row3Y, midCol3+tableWidth, row3Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "IPv6"
	}

	// row 4
	if v, err := g.SetView("top_geo", midCol1, row4Y, midCol1+tableWidth, row4Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top GeoLoc"
	}

	if v, err := g.SetView("top_asn", midCol2, row4Y, midCol2+tableWidth, row4Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top ASN"
	}

	return nil

}

func doDNSView(g *gocui.Gui) error {

	maxX, _ := g.Size()

	//viewsWidth := 15
	viewsHeight := 7
	tableHeight := 8
	tableWidth := (maxX / 4) - 1
	row1Y := viewsHeight + 1
	row2Y := row1Y + tableHeight + 1
	row3Y := row2Y + tableHeight + 1
	//row4Y := row3Y + tableHeight + 1
	midCol1 := 0
	midCol2 := midCol1 + tableWidth + 1
	midCol3 := midCol2 + tableWidth + 1
	midCol4 := midCol3 + tableWidth + 1

	// row 1
	if v, err := g.SetView("qname2", midCol1, row1Y, midCol1+tableWidth, row1Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top QName 2"
	}
	if v, err := g.SetView("qname3", midCol2, row1Y, midCol2+tableWidth, row1Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top QName 3"
	}
	if v, err := g.SetView("nx", midCol3, row1Y, midCol3+tableWidth, row1Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top NX"
	}
	if v, err := g.SetView("slow_in", midCol4, row1Y, midCol4+tableWidth, row1Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Slow In"
	}

	// row 2
	if v, err := g.SetView("qtype", midCol1, row2Y, midCol1+tableWidth, row2Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top QTypes"
	}
	if v, err := g.SetView("rcode", midCol2, row2Y, midCol2+tableWidth, row2Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top RCodes"
	}
	if v, err := g.SetView("srvfail", midCol3, row2Y, midCol3+tableWidth, row2Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top SRVFAILS"
	}

	if v, err := g.SetView("slow_out", midCol4, row2Y, midCol4+tableWidth, row2Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Slow Out"
	}

	// row 3
	if v, err := g.SetView("refused", midCol1, row3Y, midCol1+tableWidth, row3Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top REFUSED"
	}

	if v, err := g.SetView("top_udp_ports", midCol4, row3Y, midCol4+tableWidth, row3Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top DNS UDP Ports"
	}

	return nil

}

func layout(g *gocui.Gui) error {

	maxX, _ := g.Size()

	viewsWidth := 15
	viewsHeight := 7
	//tableHeight := 10
	//tableWidth := (maxX / 4) - 1
	row1Y := viewsHeight + 1
	//row2Y := row1Y + tableHeight + 1
	//row3Y := row2Y + tableHeight + 1
	//midCol1 := 0
	//midCol2 := midCol1 + tableWidth + 1
	//midCol3 := midCol2 + tableWidth + 1
	//midCol4 := midCol3 + tableWidth + 1

	//if v, err := g.SetView("views", 0, 0, viewsWidth, viewsHeight); err != nil {
	//	if err != gocui.ErrUnknownView {
	//		return err
	//	}
	//	v.Title = "Views"
	//	v.Highlight = true
	//	v.SelBgColor = gocui.ColorGreen
	//	v.SelFgColor = gocui.ColorBlack
	//	fmt.Fprintln(v, "Main")
	//	fmt.Fprintln(v, "DNS")
	//	if _, err := g.SetCurrentView("views"); err != nil {
	//		return err
	//	}
	//}

	if v, err := g.SetView("header", viewsWidth-viewsWidth, 0, maxX-3, row1Y-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "pktvisor v3"
	}

	//if currentView == "main" {
	//	err := doMainView(g)
	//	if err != nil {
	//		return err
	//	}
	//} else if currentView == "dns" {
	//	err := doDNSView(g)
	//	if err != nil {
	//		return err
	//	}
	//}
	doMainView(g)
	doDNSView(g)

	return nil
}

//func cursorDown(g *gocui.Gui, v *gocui.View) error {
//	if v != nil {
//		cx, cy := v.Cursor()
//		if err := v.SetCursor(cx, cy+1); err != nil {
//			ox, oy := v.Origin()
//			if err := v.SetOrigin(ox, oy+1); err != nil {
//				return err
//			}
//		}
//		if currentView == "main" {
//			currentView = "dns"
//		} else if currentView == "dns" {
//			currentView = "main"
//		}
//	}
//	updateViews(g)
//	return nil
//}
//
//func cursorUp(g *gocui.Gui, v *gocui.View) error {
//	if v != nil {
//		ox, oy := v.Origin()
//		cx, cy := v.Cursor()
//		if err := v.SetCursor(cx, cy-1); err != nil && oy > 0 {
//			if err := v.SetOrigin(ox, oy-1); err != nil {
//				return err
//			}
//		}
//	}
//	return nil
//}
//
func keybindings(g *gocui.Gui) error {
	if err := g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		return err
	}
	//if err := g.SetKeybinding("views", gocui.KeyArrowDown, gocui.ModNone, cursorDown); err != nil {
	//	return err
	//}
	//if err := g.SetKeybinding("views", gocui.KeyArrowUp, gocui.ModNone, cursorUp); err != nil {
	//	return err
	//}
	return nil
}

func quit(g *gocui.Gui, v *gocui.View) error {
	close(done)
	return gocui.ErrQuit
}

func getStats() (StatSnapshot, InstantRates, error) {

	url := fmt.Sprintf("http://%s:%d/api/v1/metrics/window/5", statHost, statPort)

	spaceClient := http.Client{
		Timeout: time.Second * 2, // Maximum of 2 secs
	}

	var rawStats map[string]StatSnapshot
	var rawRates InstantRates
	var emptyStats StatSnapshot

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return emptyStats, rawRates, err
	}

	res, getErr := spaceClient.Do(req)
	if getErr != nil {
		return emptyStats, rawRates, getErr
	}
	if res.StatusCode != 200 {
		return emptyStats, rawRates, errors.New("500 error from pktvisord getting stats")
	}

	data, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		return emptyStats, rawRates, readErr
	}

	err = json.Unmarshal(data, &rawStats)
	if err != nil {
		return emptyStats, rawRates, err
	}

	url = fmt.Sprintf("http://%s:%d/api/v1/metrics/rates", statHost, statPort)

	req, err = http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return emptyStats, rawRates, err
	}

	res, getErr = spaceClient.Do(req)
	if getErr != nil {
		return emptyStats, rawRates, getErr
	}
	if res.StatusCode != 200 {
		return emptyStats, rawRates, errors.New("500 error from pktvisord getting stats")
	}

	data, readErr = ioutil.ReadAll(res.Body)
	if readErr != nil {
		return emptyStats, rawRates, readErr
	}

	err = json.Unmarshal(data, &rawRates)
	if err != nil {
		return emptyStats, rawRates, err
	}

	return rawStats["5m"], rawRates, nil
}

func updateViews(g *gocui.Gui) {
	stats, rates, err := getStats()
	if err != nil {
		g.Close()
		panic(err)
	}
	g.Update(func(g *gocui.Gui) error {
		v, err := g.View("header")
		if err != nil {
			return err
		}
		updateHeader(v, &rates, &stats)
		currentView = "main"
		if currentView == "main" {
			v, err = g.View("top_ipv4")
			if err != nil {
				return err
			}
			updateTable(stats.Packets.TopIpv4, v, stats.Packets.DeepSamples)
			v, err = g.View("top_ipv6")
			if err != nil {
				return err
			}
			updateTable(stats.Packets.TopIpv6, v, stats.Packets.DeepSamples)
			v, err = g.View("top_geo")
			if err != nil {
				return err
			}
			updateTable(stats.Packets.TopGeoLoc, v, stats.Packets.DeepSamples)
			v, err = g.View("top_asn")
			if err != nil {
				return err
			}
			updateTable(stats.Packets.TopASN, v, stats.Packets.DeepSamples)
		}
		currentView = "dns"
		if currentView == "dns" {
			// we need to figure in the current sampling rate
			sampleRate := float64(stats.Packets.DeepSamples) / float64(stats.Packets.Total)
			wireSample := int64(float64(stats.DNS.WirePackets.Total) * sampleRate)
			replySample := int64(float64(stats.DNS.WirePackets.Replies) * sampleRate)
			xactSample := int64(float64(stats.DNS.Xact.Counts.Total) * sampleRate)
			v, err = g.View("qname2")
			if err != nil {
				return err
			}
			updateTable(stats.DNS.TopQname2, v, wireSample)
			v, err = g.View("qname3")
			if err != nil {
				return err
			}
			updateTable(stats.DNS.TopQname3, v, wireSample)
			v, err = g.View("nx")
			if err != nil {
				return err
			}
			updateTable(stats.DNS.TopNX, v, replySample)
			v, err = g.View("rcode")
			if err != nil {
				return err
			}
			updateTable(stats.DNS.TopRcode, v, replySample)
			v, err = g.View("srvfail")
			if err != nil {
				return err
			}
			updateTable(stats.DNS.TopSRVFAIL, v, replySample)
			v, err = g.View("refused")
			if err != nil {
				return err
			}
			updateTable(stats.DNS.TopREFUSED, v, replySample)
			v, err = g.View("qtype")
			if err != nil {
				return err
			}
			updateTable(stats.DNS.TopQtype, v, wireSample)
			v, err = g.View("top_udp_ports")
			if err != nil {
				return err
			}
			updateTable(stats.DNS.TopUDPPorts, v, wireSample)
			v, err = g.View("slow_in")
			if err != nil {
				return err
			}
			updateTable(stats.DNS.Xact.In.TopSlow, v, xactSample)
			v, err = g.View("slow_out")
			if err != nil {
				return err
			}
			updateTable(stats.DNS.Xact.Out.TopSlow, v, xactSample)
		}
		return nil
	})

}

func counter(g *gocui.Gui) {
	updateViews(g)
	for {
		select {
		case <-done:
			return
		case <-time.After(time.Second * time.Duration(refreshPeriod)):
			updateViews(g)
		}
	}
}
