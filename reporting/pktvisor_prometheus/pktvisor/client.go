package pktvisor

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/prometheus/common/log"
)

type NameCount struct {
	Name     string `json:"name"`
	Estimate int64  `json:"estimate"`
}

type AppSnapshot struct {
	App struct {
		DeepSampleRatePct int64   `json:"deep_sample_rate_pct"`
		Periods           int64   `json:"periods"`
		SingleSummary     bool    `json:"single_summary"`
		UpTimeMin         float64 `json:"up_time_min"`
		Version           string  `json:"version"`
	} `json:"app"`
	Dns struct {
		Xact struct {
			Open int64 `json:"open"`
		} `json:"xact"`
	} `json:"dns"`
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

type Client struct {
	Timeout           time.Duration
	ConnectionRetries int
}

func NewClient(timeout time.Duration, connectionRetries int) *Client {
	return &Client{time.Duration(timeout), connectionRetries}
}

// getResponse collects an individual http.response and returns a *Response
func (c Client) getResponse(url string) ([]byte, error) {

	log.Debugf("Fetching %s \n", url)

	resp, err := c.getHTTPResponse(url) // do this earlier

	if err != nil {
		return nil, fmt.Errorf("Error converting body to byte array: %v", err)
	}

	// Read the body to a byte array so it can be used elsewhere
	body, err := ioutil.ReadAll(resp.Body)

	defer resp.Body.Close()

	if err != nil {
		return nil, fmt.Errorf("Error converting body to byte array: %v", err)
	}

	return body, nil
}

// getHTTPResponse handles the http client creation, token setting and returns the *http.response
func (c Client) getHTTPResponse(url string) (*http.Response, error) {

	client := &http.Client{
		Timeout: c.Timeout,
	}

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, fmt.Errorf("Failed to create http request: %v", err)
	}

	var retries = c.ConnectionRetries
	for retries > 0 {
		resp, err := client.Do(req)
		if err != nil {
			retries -= 1

			if retries == 0 {
				return nil, err
			} else {
				log.Infof("Retrying HTTP request %s", url)
			}
		} else {
			return resp, nil
		}
	}
	return nil, nil
}

func (c *Client) GetAppStats(host string, port string) (AppSnapshot, error) {
	var rawStats AppSnapshot
	var emptyStats AppSnapshot

	url := fmt.Sprintf("http://%s:%s/api/v1/metrics/app", host, port)

	data, readErr := c.getResponse(url)
	if readErr != nil {
		return emptyStats, readErr
	}

	err := json.Unmarshal(data, &rawStats)
	if err != nil {
		return emptyStats, err
	}

	return rawStats, nil
}

func (c *Client) GetBucketStats(host string, port string, duration int) (StatSnapshot, error) {
	var rawStats map[string]StatSnapshot
	var emptyStats StatSnapshot

	url := fmt.Sprintf("http://%s:%s/api/v1/metrics/bucket/%d", host, port, duration)

	data, readErr := c.getResponse(url)
	if readErr != nil {
		return emptyStats, readErr
	}

	err := json.Unmarshal(data, &rawStats)
	if err != nil {
		return emptyStats, err
	}

	return rawStats["1m"], nil
}
