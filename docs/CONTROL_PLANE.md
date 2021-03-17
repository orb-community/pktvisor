# Control Plane

**_Draft_**

pktvisord exposes a control plane over REST API.

## Discovery

pktvisord exposes a method for discovering the available modules, their configurable properties, and their associated
metrics schema.

All interfaces and schemas are versioned.

```
/api/v1/inputs
 {
  pcap: "1.0"
 }
/api/v1/inputs/pcap/interface
 {
  version: "1.0",
  config: {
   iface: {
     type: "string",
     description: "the ethernet interface to capture on"
   }
  }
  filters: {
    bpf: {
     type: "string",
     description: "tcpdump compatible bpf filter expression"
    }
  },
  metric_groups: {
  }
 }
/api/v1/handlers
 { dns: { version: "1.0" }, 
   net: { version: "1.0" } }
/api/v1/handlers/dns/interface
 {
  version: "1.0",
  config: {
    periods: {
     type: "int",
     description: "number of metric periods to keep"
    }
  }
  filters: {
    qname_suffix: {
     type: "string",
     description: "match the DNS qname sufix given", 
     regex: "..."
    }
  },
  metric_groups: {
    top_error_qnames: {
      description: "top N qnames with error result codes", 
      metrics: {,
       top_refused: {
        "type": "top_n",
         "description": "..."
       },
       top_srvfail: {
        "type": "top_n",
         "description": "..."
       }, 
       top_nxdomain: {
        "type": "top_n",
         "description": "..."
       },
      }
    }, 
    transactions: {
      description: "information on query/reply pairs", 
      metrics: {
      ...
      }
    }
  }
 }
/api/v1/handlers/net/interface
 {
 }
```

