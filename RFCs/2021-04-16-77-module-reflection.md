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
  "config": {
    "iface": {
      "required": true,
      "type": "string",
      "title": "Interface",
      "description": "The ethernet interface to capture on"
    },
    "bpf": {
      "required": false,
      "type": "string",
      "title": "Filter Expression",
      "description": "tcpdump compatible filter expression for limiting the traffic examined (with BPF). Example: \"port 53\""
    },
    "host_spec": {
      "required": false,
      "type": "string",
      "title": "Host Specification",
      "description": "Subnets (comma separated) to consider this HOST, in CIDR form. Example: \"10.0.1.0/24,10.0.2.1/32,2001:db8::/64\""
    },
    "pcap_source": {
      "required": false,
      "type": "string",
      "title": "pcap Engine",
      "description": "pcap backend engine to use. Defaults to best for platform."
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
  "config": {
    "filter_exclude_noerror": {
      "title": "Filter: Exclude NOERROR",
      "type": "bool",
      "description": "Filter out all NOERROR responses"
    },
    "filter_only_rcode": {
      "title": "Filter: Include Only RCode",
      "type": "integer",
      "description": "Filter out any queries which are not the given RCODE"
    },
    "filter_only_qname_suffix": {
      "title": "Filter: Include Only QName With Suffix",
      "type": "array[string]",
      "description": "Filter out any queries whose QName does not end in a suffix on the list"
    }
  },
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
  "config": {
  },
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

