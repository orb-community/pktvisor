/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"pktvisor/internal/ui"

	"github.com/jroimartin/gocui"
	"net/http"
	"pktvisor/pkg/client"
)

func main() {
	usage := `pktvisor-cli command line UI

Usage:
  pktvisor-cli [-p PORT] [-H HOST]
  pktvisor-cli -h
  pktvisor-cli --version

Options:
  -p PORT               Query pktvisord metrics webserver on the given port [default: 10853]
  -H HOST               Query pktvisord metrics webserver on the given host [default: localhost]
  -P POLICY             pktvisor policy to query [default: default]
  --tls					Use TLS to communicate with pktvisord metrics webserver
  --tls-noverify		Do not verify TLS certificate
  -h                    Show this screen
  --version             Show client version`

	wantTLS := flag.Bool("tls", false, "Use TLS to communicate with pktvisord metrics webserver")
	wantTLSNoVerify := flag.Bool("tls-noverify", false, "Use TLS to communicate with pktvisord metrics webserver, do not verify TLS certificate")
	wantVersion := flag.Bool("version", false, "Show client version")
	wantHelp := flag.Bool("h", false, "Show help")
	fPort := flag.Int("p", 10853, "Query pktvisord metrics webserver on the given port")
	fHost := flag.String("H", "localhost", "Query pktvisord metrics webserver on the given host")
	pPolicy := flag.String("P", "default", "pktvisor policy to query")
	flag.Parse()

	if *wantVersion {
		fmt.Println(client.VisorVersionNum)
		return
	}
	if *wantHelp {
		fmt.Println(usage)
		return
	}

	config := client.ClientConfig{
		Host:          *fHost,
		Port:          *fPort,
		DefaultPolicy: *pPolicy,
	}

	if *wantTLS || *wantTLSNoVerify {
		config.Protocol = "https"
		if *wantTLSNoVerify {
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
	}

	c, err := client.New(config)
	if err != nil {
		log.Panicln(err)
	}

	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		log.Panicln(err)
	}
	defer g.Close()

	u, err := ui.New(g, c, 1)
	if err != nil {
		log.Panicln(err)
	}
	u.Start()

}
