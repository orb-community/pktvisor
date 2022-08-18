/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

package ui

import (
	"context"
	"fmt"
	"log"
	"pktvisor/pkg/client"
	"strconv"
	"time"

	"github.com/jroimartin/gocui"
)

type UI interface {
	Start()
}

type ui struct {
	refresh     int
	client      client.Client
	gui         *gocui.Gui
	currentView string
}

func (u *ui) Start() {
	u.gui.SetManager(u)

	if err := u.keybindings(); err != nil {
		log.Println(err)
	}

	ctx, cncl := context.WithCancel(context.Background())
	defer cncl()

	go u.counter(ctx)

	if err := u.gui.MainLoop(); err != nil && err != gocui.ErrQuit {
		maxX, maxY := u.gui.Size()
		log.Println("%s, terminal max size: %d, %d\n", err, maxX, maxY)
	}
}

func New(gui *gocui.Gui, client client.Client, refresh int) (UI, error) {
	return &ui{
		refresh: refresh,
		gui:     gui,
		client:  client,
	}, nil
}

//func (u *ui) cursorDown(g *gocui.Gui, v *gocui.View) error {
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
//func (u *ui) cursorUp(g *gocui.Gui, v *gocui.View) error {
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
func (u *ui) keybindings() error {
	if err := u.gui.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, u.quit); err != nil {
		return err
	}
	//if err :=u.gui.SetKeybinding("views", gocui.KeyArrowDown, gocui.ModNone, cursorDown); err != nil {
	//	return err
	//}
	//if err :=u.gui.SetKeybinding("views", gocui.KeyArrowUp, gocui.ModNone, cursorUp); err != nil {
	//	return err
	//}
	return nil
}

func (u *ui) updateTable(data []client.NameCount, v *gocui.View, baseNumber int64) {
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
		fmt.Fprintf(v, "%-"+strconv.Itoa(w-len(numStr)-1)+"s %s\n", stat.Name, numStr)
		top3++
	}
}

func (u *ui) doMainView() error {
	maxX, _ := u.gui.Size()

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

	if v, err := u.gui.SetView("top_ipv4", midCol2, row3Y, midCol2+tableWidth, row3Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "IPv4"
	}

	if v, err := u.gui.SetView("top_ipv6", midCol3, row3Y, midCol3+tableWidth, row3Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "IPv6"
	}

	// row 4
	if v, err := u.gui.SetView("top_geo", midCol1, row4Y, midCol1+tableWidth, row4Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top GeoLoc"
	}

	if v, err := u.gui.SetView("top_asn", midCol2, row4Y, midCol2+tableWidth, row4Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top ASN"
	}

	return nil

}

func (u *ui) Layout(g *gocui.Gui) error {

	maxX, _ := u.gui.Size()

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

	//if v, err :=u.gui.SetView("views", 0, 0, viewsWidth, viewsHeight); err != nil {
	//	if err != gocui.ErrUnknownView {
	//		return err
	//	}
	//	v.Title = "Views"
	//	v.Highlight = true
	//	v.SelBgColor = gocui.ColorGreen
	//	v.SelFgColor = gocui.ColorBlack
	//	fmt.Fprintln(v, "Main")
	//	fmt.Fprintln(v, "DNS")
	//	if _, err :=u.gui.SetCurrentView("views"); err != nil {
	//		return err
	//	}
	//}

	if v, err := u.gui.SetView("header", 0, 0, maxX-3, row1Y-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = fmt.Sprintf("pktvisor-cli (client: %s | server: %s) Policy: %s", client.VisorVersionNum, u.client.GetServerVersion(), u.client.GetPolicy())
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
	u.doMainView()
	u.doDNSView()

	return nil
}

func (u *ui) quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

func (u *ui) updateViews() {
	stats, err := u.client.GetStats()
	if err != nil {
		log.Println(err)
		return
	}
	u.gui.Update(func(g *gocui.Gui) error {
		v, err := u.gui.View("header")
		if err != nil {
			return err
		}
		u.updateHeader(v, stats)
		u.currentView = "main"
		if u.currentView == "main" {
			v, err = u.gui.View("top_ipv4")
			if err != nil {
				return err
			}
			u.updateTable(stats.Packets.TopIpv4, v, stats.Packets.DeepSamples)
			v, err = u.gui.View("top_ipv6")
			if err != nil {
				return err
			}
			u.updateTable(stats.Packets.TopIpv6, v, stats.Packets.DeepSamples)
			v, err = u.gui.View("top_geo")
			if err != nil {
				return err
			}
			u.updateTable(stats.Packets.TopGeoLoc, v, stats.Packets.DeepSamples)
			v, err = u.gui.View("top_asn")
			if err != nil {
				return err
			}
			u.updateTable(stats.Packets.TopASN, v, stats.Packets.DeepSamples)
		}
		u.currentView = "dns"
		if u.currentView == "dns" {
			// we need to figure in the current sampling rate
			sampleRate := float64(stats.Packets.DeepSamples) / float64(stats.Packets.Total)
			wireSample := int64(float64(stats.DNS.WirePackets.Total) * sampleRate)
			replySample := int64(float64(stats.DNS.WirePackets.Replies) * sampleRate)
			xactSample := int64(float64(stats.DNS.Xact.Counts.Total) * sampleRate)
			v, err = u.gui.View("qname2")
			if err != nil {
				return err
			}
			u.updateTable(stats.DNS.TopQname2, v, wireSample)
			v, err = u.gui.View("qname3")
			if err != nil {
				return err
			}
			u.updateTable(stats.DNS.TopQname3, v, wireSample)
			v, err = u.gui.View("nx")
			if err != nil {
				return err
			}
			u.updateTable(stats.DNS.TopNxdomain, v, replySample)
			v, err = u.gui.View("rcode")
			if err != nil {
				return err
			}
			u.updateTable(stats.DNS.TopRcode, v, replySample)
			v, err = u.gui.View("srvfail")
			if err != nil {
				return err
			}
			u.updateTable(stats.DNS.TopSRVFAIL, v, replySample)
			v, err = u.gui.View("refused")
			if err != nil {
				return err
			}
			u.updateTable(stats.DNS.TopREFUSED, v, replySample)
			v, err = u.gui.View("qtype")
			if err != nil {
				return err
			}
			u.updateTable(stats.DNS.TopQtype, v, wireSample)
			v, err = u.gui.View("top_udp_ports")
			if err != nil {
				return err
			}
			u.updateTable(stats.DNS.TopUDPPorts, v, wireSample)
			v, err = u.gui.View("slow_in")
			if err != nil {
				return err
			}
			u.updateTable(stats.DNS.Xact.In.TopSlow, v, xactSample)
			v, err = u.gui.View("slow_out")
			if err != nil {
				return err
			}
			u.updateTable(stats.DNS.Xact.Out.TopSlow, v, xactSample)
		}
		return nil
	})

}

func (u *ui) counter(ctx context.Context) {
	u.updateViews()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second * time.Duration(u.refresh)):
			u.updateViews()
		}
	}
}
