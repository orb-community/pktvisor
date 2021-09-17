/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

package ui

import "github.com/jroimartin/gocui"

func (u *ui) doDNSView() error {

	maxX, _ := u.gui.Size()

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
	if v, err := u.gui.SetView("qname2", midCol1, row1Y, midCol1+tableWidth, row1Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top QName 2"
	}
	if v, err := u.gui.SetView("qname3", midCol2, row1Y, midCol2+tableWidth, row1Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top QName 3"
	}
	if v, err := u.gui.SetView("nx", midCol3, row1Y, midCol3+tableWidth, row1Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top NX"
	}
	if v, err := u.gui.SetView("slow_in", midCol4, row1Y, midCol4+tableWidth, row1Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Slow In"
	}

	// row 2
	if v, err := u.gui.SetView("qtype", midCol1, row2Y, midCol1+tableWidth, row2Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top QTypes"
	}
	if v, err := u.gui.SetView("rcode", midCol2, row2Y, midCol2+tableWidth, row2Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top RCodes"
	}
	if v, err := u.gui.SetView("srvfail", midCol3, row2Y, midCol3+tableWidth, row2Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top SRVFAILS"
	}

	if v, err := u.gui.SetView("slow_out", midCol4, row2Y, midCol4+tableWidth, row2Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Slow Out"
	}

	// row 3
	if v, err := u.gui.SetView("refused", midCol1, row3Y, midCol1+tableWidth, row3Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top REFUSED"
	}

	if v, err := u.gui.SetView("top_udp_ports", midCol4, row3Y, midCol4+tableWidth, row3Y+tableHeight); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Top DNS UDP Ports"
	}

	return nil

}
