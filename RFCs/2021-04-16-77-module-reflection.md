# Module Reflection

## Summary

pktvisord exposes a method for discovering the available modules, their configurable properties, and their associated
metrics schema.

All interfaces and schemas are versioned.

```
GET /api/v1/inputs
 {
  "pcap": {"version", "1.0"},
  "dnstap": {"version", "1.0"}
 }
GET /api/v1/inputs/pcap/features
 {
  "version": "1.0",
  "info": {
    "available_interfaces": {
      "eth0": {}
    }
  },
 "config": {
  "iface": {
    "type": "string",
    "description": "the ethernet interface to capture on"
   }
  }
 "filters": {
   "bpf": {
    "type": "string",
    "description": "tcpdump compatible filter expression"
    }
  }
 }
GET /api/v1/inputs/dnstap/features
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
GET /api/v1/handlers
 {"dns": {"version": "1.0" }, 
  "net": {"version": "1.0" },
  "pcap": {"version": "1.0"}}
GET /api/v1/handlers/dns/features
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
     "metrics": {,
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
       },
      }
    }, 
   "transactions": {
     "description": "information on query/reply pairs", 
     "metrics": {
      ...
      }
    }
  }
 }
GET /api/v1/handlers/net/features
 {
 }
```

