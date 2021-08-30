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
      "name": "Interface",
      "description": "The ethernet interface to capture on"
    },
    "bpf": {
      "required": false,
      "type": "string",
      "name": "Filter Expression",
      "description": "tcpdump compatible filter expression for limiting the traffic examined (with BPF). Example: \"port 53\""
    },
    "host_spec": {
      "required": false,
      "type": "string",
      "name": "Host Specification",
      "description": "Subnets (comma separated) to consider this HOST, in CIDR form. Example: \"10.0.1.0/24,10.0.2.1/32,2001:db8::/64\""
    },
    "pcap_source": {
      "required": false,
      "type": "string",
      "name": "pcap Engine",
      "description": "pcap backend engine to use. Defaults to best for platform."
    }
  }
}
```

`GET /api/v1/inputs/dnstap/features`

```json
 {
  "version": "1.0",
  "config": {
    "socket": {
      "type": "string",
      "description": "the dnstap socket to listen to"
    }
  }
  "filters": {
    "qname_suffix": {
      "type": "string",
      "description": "match the DNS qname sufix given",
      "regex": "..."
    }
  },
  "metric_groups": {
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
    "periods": {
      "type": "int",
      "description": "number of metric periods to keep"
    }
  }
  "filters": {
    "qname_suffix": {
      "type": "string",
      "description": "match the DNS qname sufix given",
      "regex": "..."
    }
  },
  "metric_groups": {
    "top_error_qnames": {
      "description": "top N qnames with error result codes",
      "metrics": {
        ,
      "top_refused": {
        "type": "top_n",
        "description": "..."
      },
      "top_srvfail": {
        "type": "top_n",
        "description": "..."
      },
      "top_nxdomain": {
        "type": "top_n",
        "description": "..."
      }
    }
  },
  "transactions": {
    "description": "information on query/reply pairs",
    "metrics": {
    }
  }
}
}
```

`GET /api/v1/handlers/net/features`

```json
{
}
```

