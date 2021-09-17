/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

package client

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type Client interface {
	GetStats() (*StatSnapshot, error)
	GetServerVersion() string
}

type ClientConfig struct {
	Host          string
	Port          int
	Protocol      string
	DefaultPolicy string
}

type client struct {
	config        ClientConfig
	serverVersion string
}

func (c *client) GetServerVersion() string {
	if c.serverVersion != "" {
		return c.serverVersion
	}
	var appMetrics AppMetrics
	URL := fmt.Sprintf("%s://%s:%d/api/v1/metrics/app", c.config.Protocol, c.config.Host, c.config.Port)
	err := c.getMetrics(URL, &appMetrics)
	if err != nil {
		log.Println(err)
	}
	c.serverVersion = appMetrics.App.Version
	return c.serverVersion
}

func New(config ClientConfig) (Client, error) {
	return &client{
		config: config,
	}, nil
}

func (c *client) getMetrics(url string, payload interface{}) error {
	spaceClient := http.Client{
		Timeout: time.Second * 30,
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	res, getErr := spaceClient.Do(req)
	if getErr != nil {
		return getErr
	}
	if res.StatusCode != 200 {
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return errors.New(fmt.Sprintf("non 200 HTTP error code from pktvisord, no or invalid body: %d", res.StatusCode))
		}
		if body[0] == '{' {
			var jsonBody map[string]interface{}
			err := json.Unmarshal(body, &jsonBody)
			if err == nil {
				if errMsg, ok := jsonBody["error"]; ok {
					return errors.New(fmt.Sprintf("%d %s", res.StatusCode, errMsg))
				}
			}
		}
		return errors.New(fmt.Sprintf("%d %s", res.StatusCode, body))
	}

	err = json.NewDecoder(res.Body).Decode(&payload)
	if err != nil {
		return err
	}
	return nil
}

func (c *client) GetStats() (*StatSnapshot, error) {
	var rawStats map[string]map[string]interface{}
	err := c.getMetrics(fmt.Sprintf("%s://%s:%d/api/v1/policies/%s/metrics/window/5", c.config.Protocol, c.config.Host, c.config.Port, c.config.DefaultPolicy), &rawStats)
	if err != nil {
		return nil, err
	}
	stats := StatSnapshot{}
	//for handlerName, handlerData := range rawStats {
	//	_, isDns := handlerData["dns"]
	//	_, isPackets := handlerData["packets"]
	//	_, isPcap := handlerData["pcap"]
	//	if isPcap {
	//		stats.Pcap.OsDrops = handlerData["pcap"]
	//	}
	//}
	return &stats, nil
}
