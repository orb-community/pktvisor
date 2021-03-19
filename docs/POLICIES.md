# Orb and pktvisor Policy Driven Configuration

**_Draft_**

Orb and pktvisor observability configuration is policy driven.

pktvisor maybe run stand alone, or with the Orb control plane. In the latter configuration, orb-agent controls the
pktvisord process and allows centralized configuration via orb-api.

## Base Concepts

### pktvisor Taps

Taps are named, host specific connections to raw stream data accessed by pktvisord. They represent configuration data
only; they do not cause any processing to take place in pktvisord. They should be referenced by Collection Policies by
name (see below).

Taps may be configured on the command line at agent start up (often using a configuration management system) either
directly in pktvisord (via command line or admin API) when running stand alone, or indirectly via orb-agent. See Command
Line Examples below.

`taps.yaml`

```yaml
version: "1.0"

policy:
  # each tap has input module specific configuration options
  taps:
    # a pcap tap which uses eth0 and is referenced by the identifier "anycast"
    anycast:
      type: pcap
      config:
        iface: eth0
    # an sflow tap which listens on the given IP and port, referenced by the identifier "pop_switch"
    pop_switch:
      type: sflow
      config:
        port: 6343
        bind: 192.168.1.1
    # a dnstap tap which gets its stream from the given socket, named "trex_tap"
    trex_tap:
      type: dnstap
      config:
        socket: /var/dns.sock
```

### pktvisor Collection Policies

Collection policies direct pktvisor to use taps to create an instance of an input stream (possibly with a filter), and
attach handlers to it. Processing takes place, and the data is exposed for sinks to collect. These policies may be given
directly to pktvisor (via command line or admin API) in standalone mode, or via Orb control plane (in which case they
are not stored in a file, but rather in the control plane database).

`collection-policy-anycast.yaml`

```yaml
version: "1.0"

policy:
  collection:
    # policy name and description
    anycast_dns:
      description: "base anycast DNS policy"
      # input stream to create based on the given tap and optional filter config
      input:
        # this must reference a tap name, or application of the policy will fail
        tap: anycast
        # this must match the type of the matching tap name. or application of the policy will fail
        type: pcap
        filter:
          bpf: "port 53"
      # stream handlers to attach to this input stream
      # these decide exactly which data to summarize and expose for collection
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

### Standalone Command Line Example

#### Standalone agent start up

When running without Orb, the tap and the collection config can be passed directly to pktvisor.

```shell
$ pktvisord --config taps.yaml --config collection-policy-anycast.yaml
```

They may also be combined into a single YAML file (the schemas will merge) and passed in with one `--config` option.

The admin-api (or prometheus output, pktvisor-cli, etc) should then be used to collect the results manually.

## Orb Concepts

Orb moves most of the configuration to a central control plane. The only configuration that remains at the agent is the
Tap configuration (because it is host specific), and Vitals configuration (below).

### Vitals and Selector Configurations

Orb needs the ability to address the agents that it is controlling. It does this by matching Selectors with Vitals.

#### Vitals

orb-agent is told on startup what its Vitals are: these are arbitrary key value pairs which typically represent
information such as region, pop, and node type.

`vitals.yaml`

```yaml
version: "1.0"

policy:
  vitals:
    region: EU
    pop: ams02
    node_type: dns
```

#### vitals on orb-agent start up

```shell
$ orb-agent --config vitals.yaml
```

#### combining vitals and taps on orb-agent start up

Since both Taps and Vitals are necessary for orb-agent start up, you can pass both in via two separate config files:

```shell
$ orb-agent --config taps.yaml --config vitals.yaml
```

Or instead combine them into a single file:

`orb-agent.yaml`

```yaml
version: "1.0"

policy:
  taps:
    anycast:
      type: pcap
      config:
        iface: eth0
  vitals:
    region: EU
    pop: ams02
    node_type: dns
```

```shell
$ orb-agent --config orb-agent.yaml
```

### Orb Selectors

Selectors are named configurations of arbitrary key value pairs which can match against the Vitals of the agents
available in the Orb ecosystem. They may be thought of as groups of agents. These names are referenced in Orb Policies.
pktvisord does not read this configuration or use this data; it is used only by orb-agent. This schema is found only in
the control plane, not on the command line or in files.

```yaml
version: "1.0"

policy:
  selectors:
    all_dns:
      node_type: dns
    eu_dns:
      region: EU
      node_type: dns
```

### Orb Sinks

Orb includes a metric collection system. Sinks specify where to send the summarized metric data. pktvisord does not read
this configuration or use this data; it is used only by orb-agent. This schema is found only in the control plane, not
on the command line or in files.

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

### Orb Policies

An Orb policy ties together Selectors, a Collection Policy, and one or more Sinks. pktvisord does not read this
configuration or use this data; it is used only by orb-agent. This schema is found only in the control plane, not on the
command line or in files.

orb-agent will be made aware of the collection policy and the sinks if this selector matches its vitals. In case of a
match, orb-agent will attempt to apply the collection policy to its pktvisord, and update the control plane about
success or failure. Upon success, the sink will be created.

```yaml
version: "1.0"

policy:
  orb:
    selectors:
      - eu_dns
    collection_policy: anycast_dns
    sinks:
      - default_prometheus
```









