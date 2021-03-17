# Policies

**_Draft_**

pktvisord metric collection is policy driven. Policies act as a grouping of an input stream to associated stream
handlers.

## Property Attributes

* Policies have exactly one Input source
* Policies have an unlimited number of Stream Handlers
* Policies contain configuration data, e.g.
  * Time window length (number of periods)
  * Maximum deep sample rate

## Policy Semantics

* The REST API path schema enforces the hierarchy of Policy -> Input => Handlers

```
/api/v1/policy/:POLICY_NAME:/:INPUT_MODULE_TYPE:/handler/:HANDLER_MODULE_TYPE:/:HANDLER_NAME:/<handler type specific>
```

```
/api/v1/policy/anycast/pcap/handler/dns/default/bucket/0
/api/v1/policy/anycast/pcap/handler/net/default/bucket/0
/api/v1/policy/anycast/pcap/handler/dns/special_domain/bucket/0

/api/v1/policy/management/pcap/handler/dns/default/bucket/0
/api/v1/policy/management/pcap/handler/net/default/bucket/0
```

## Policy Schema

* Policy schema is represented by YAML
* The schema may represent policy information not directly used by pktvisor, such as where to send output
* The schema is versioned

## Example (YAML)

```yaml
version: "1.0"

policy:
  input:
    anycast:
      type: pcap
      config:
        bpf: "host 192.168.0.50"
        iface: eth0
  handlers:
    config:
      periods: 5
      max_deep_sample: 50
    modules:
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
        config:
          qname_match: .mydomain.com
        metrics:
          disable:
            - top_qtypes
            - top_udp_ports
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









