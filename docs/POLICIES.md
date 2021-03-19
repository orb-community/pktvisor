# Policies

**_Draft_**

pktvisord observability configuration is policy driven. Policies act as a grouping of an input stream to stream
handlers, and their associated configuration.

## Property Attributes

* Policies have exactly one Input source
* Policies have an unlimited number of Stream Handlers
* Policies have an unlimited number of Sinks (which is not used directly by pktvisord; see Orb)
* Policies contain configuration data, including observability filters and metric collection configuration.

## Policy Semantics

* The REST API path schema enforces the hierarchy of Policy -> Input => Handlers

```
/api/v1/policy/:POLICY_NAME:/:INPUT_MODULE_TYPE:/handler/:HANDLER_MODULE_TYPE:/:HANDLER_NAME:/<handler type specific>
```

Examples:

```
/api/v1/policy/anycast/pcap/handler/dns/default_dns/bucket/0
/api/v1/policy/anycast/pcap/handler/net/default_net/bucket/0
/api/v1/policy/anycast/pcap/handler/dns/special_domain/bucket/0

/api/v1/policy/management/pcap/handler/dns/dns_collection/bucket/0
/api/v1/policy/management/pcap/handler/net/net_collection/bucket/0
```

## Policy Schema

* Policy schema is represented by YAML
* The schema may represent policy information not directly used by pktvisor, such as where to send output
* The schema is versioned

## Example (YAML)

Taps are named, host specific connections to raw stream data. They represent configuration data only, they do not cause
any processing to take place. They should be referenced by policies. These may be configured on the command line at
start up (often using a configuration management system).

```shell
$ orb-agent --tap-config taps.yaml --selector-watch global/EU/ami
```

taps.yaml

```yaml
version: "1.0"

taps:
  anycast:
    type: pcap
    config:
      iface: eth0
  pop_switch:
    type: sflow
    config:
      port: 6343
      bind: 192.168.1.1
  trex_tap:
    type: dnstap
    config:
      socket: /var/dns.sock
```

Policies use taps to create an instance of an input (possibly with a filter), and attach handlers to it. Processing
takes place, and the data is exposed to sinks.

```yaml
version: "1.0"

policy:
  name: "anycast_dns"
  description: "anycast DNS policy"
  # input stream
  # only one is supported, but multiple policies may reuse host_inputs
  input:
    tap: anycast
    type: pcap
    filter:
      bpf: "port 53"
  # stream handlers 
  handlers:
    # default configuration for the stream handlers
    config:
      periods: 5
      max_deep_sample: 50
    modules:
      # the keys at this level are unique identifiers
      default_net:
        type: net
      udp_traffic:
        type: net
        config:
          protocols: [ udp ]
        metrics:
          enable:
            - top_ips
      default_dns:
        type: dns
        config:
          max_deep_sample: 75
      special_domain:
        type: dns
        # specify that the stream handler module requires >= specific version to be successfully applied 
        require_version: "1.0"
        config:
          # must match the available configuration options for this version of this stream handler
          qname_suffix: .mydomain.com
        metrics:
          disable:
            - top_qtypes
            - top_udp_ports
```

Orb: Sinks specify where to send summarized metric data.

```yaml
version: "1.0"

policy:
  sinks:
    default_prometheus:
      type: prometheus_exporter
      address: 0.0.0.0:9598
      default_namespace: service
    my_s3:
      type: aws_s3
      bucket: my-bucket
      compression: gzip
      region: us-east-1
```

Orb: Selectors indicate which agent should apply a policy.

```yaml
version: "1.0"

policy:
  selector:
    - global/EU/ams
```









