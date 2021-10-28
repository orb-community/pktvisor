# Module Reflection

## Summary

pktvisord exposes a method for discovering the available modules, their configurable properties, and their associated
metrics schema.

All interfaces and schemas are versioned.

`GET /api/v1/inputs`

```json
 {
  "pcap": {
    "version": "1.0"
  },
  "dnstap": {
    "version": "1.0"
  }
}
```

`GET /api/v1/inputs/pcap/features`

```json
 {
  "version": "1.0",
  "info": {
    "available_iface": {
      "eth0": {},
      "eth1": {}
    }
  },
  "filter": {
    "bpf": {
      "type": "string",
      "input": "text",
      "label": "Filter Expression",
      "description": "tcpdump compatible filter expression for limiting the traffic examined (with BPF). See https://www.tcpdump.org/manpages/tcpdump.1.html",
      "props": {
        "example": "udp port 53 and host 127.0.0.1"
      }
    }
  },
  "config": {
    "iface": {
      "type": "string",
      "input": "text",
      "label": "Network Interface",
      "description": "The network interface to capture traffic from",
      "props": {
        "required": true,
        "example": "eth0"
      }
    },
    "host_spec": {
      "type": "string",
      "input": "text",
      "label": "Host Specification",
      "description": "Subnets (comma separated) which should be considered belonging to this host, in CIDR form. Used for ingress/egress determination, defaults to host attached to the network interface.",
      "props": {
        "advanced": true,
        "example": "10.0.1.0/24,10.0.2.1/32,2001:db8::/64"
      }
    },
    "pcap_source": {
      "type": "string",
      "input": "select",
      "label": "Packet Capture Engine",
      "description": "Packet capture engine to use. Defaults to best for platform.",
      "props": {
        "advanced": true,
        "example": "libpcap",
        "options": {
          "libpcap": "libpcap",
          "af_packet (linux only)": "af_packet"
        }
      }
    }
  }
}
```

`GET /api/v1/handlers`

```json
 {
  "dns": {
    "version": "1.0"
  },
  "net": {
    "version": "1.0"
  },
  "pcap": {
    "version": "1.0"
  }
}
```

`GET /api/v1/handlers/dns/features`

```json
{
  "version": "1.0",
  "filter": {
    "exclude_noerror": {
      "label": "Exclude NOERROR",
      "type": "bool",
      "input": "checkbox",
      "description": "Filter out all NOERROR responses"
    },
    "only_rcode": {
      "label": "Include Only RCODE",
      "type": "number",
      "input": "select",
      "description": "Filter out any queries which are not the given RCODE",
      "props": {
        "allow_custom_options": true,
        "options": {
          "NOERROR": 0,
          "SERVFAIL": 2,
          "NXDOMAIN": 3,
          "REFUSED": 5
        }
      }
    },
    "only_qname_suffix": {
      "label": "Include Only QName With Suffix",
      "type": "string[]",
      "input": "text",
      "description": "Filter out any queries whose QName does not end in a suffix on the list",
      "props": {
        "example": ".foo.com,.example.com"
      }
    }
  },
  "config": {},
  "metrics": {
    "cardinality.qname": {
      "type": "cardinality",
      "description": "..."
    },
    "in": {
      "type": "counter",
      "description": "..."
    },
    "xact.counts.timed_out": {
      "type": "integer",
      "description": "..."
    },
    "xact.counts.total": {
      "type": "integer",
      "description": "..."
    },
    "xact.in.top_slow": {
      "type": "top_n",
      "description": "..."
    }
  },
  "metric_groups": {
    "cardinality": {
      "title": "Cardinality",
      "description": "Metrics counting the unique number of items in the stream",
      "metrics": [
        "cardinality.qname"
      ]
    },
    "dns_transactions": {
      "title": "DNS Transactions (Query/Reply pairs)",
      "description": "Metrics based on tracking queries and their associated replies",
      "metrics": [
        "xact.counts.timed_out",
        "xact.counts.total",
        "xact.in.top_slow"
      ]
    },
    "top_dns_wire": {
      "title": "Top N Metrics (Various)",
      "description": "Top N metrics across various details from the DNS wire packets",
      "metrics": [
        "..."
      ]
    },
    "top_qnames": {
      "title": "Top N QNames (All)",
      "description": "Top QNames across all DNS queries in stream",
      "metrics": [
        "..."
      ]
    },
    "top_qnames_by_rcode": {
      "title": "Top N QNames (Failing RCodes) ",
      "description": "Top QNames across failing result codes",
      "metrics": [
        "..."
      ]
    }
  }
}
```

`GET /api/v1/handlers/net/features`

```json
{
  "version": "1.0",
  "filter": { },
  "config": { },
  "metrics": {
    "cardinality.dst_ips_out": {
      "type": "cardinality",
      "description": "..."
    },
    "cardinality.src_ips_in": {
      "type": "cardinality",
      "description": "..."
    },
    "in": {
      "type": "counter",
      "description": "..."
    },
    "rates.pps_in": {
      "type": "rate",
      "description": "..."
    },
    "top_ASN": {
      "type": "top_k",
      "description": "..."
    }
  },
  "metric_groups": {
    "ip_cardinality": {
      "title": "IP Address Cardinality",
      "description": "Unique IP addresses seen in the stream",
      "metrics": [
        "cardinality.dst_ips_out",
        "cardinality.src_ips_in"
      ]
    },
    "top_geo": {
      "title": "Top Geo",
      "description": "Top Geo IP and ASN in the stream",
      "metrics": [
        "top_ASN",
        "top_geoLoc"
      ]
    },
    "top_ips": {
      "title": "Top IPs",
      "description": "Top IP addresses in the stream",
      "metrics": [
        "top_ipv4",
        "top_ipv6"
      ]
    }
  }
}
```

